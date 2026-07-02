"""Multi-Agent Security Orchestrator — the swarm.

Clean, minimal, professional output. No messy interleaved prints.
Phase-based summaries with small creative signs.

  ◆ phase marker     ▸ phase start     ✓ completed     ✗ failed
  │ agent activity   ⏱ timing          → result

Architecture:
  Phase 1: Recon + Enum ─── asyncio.gather (PARALLEL)
  Phase 2: Vuln Scan ───── sequential (depends on recon)
  Phase 3: Verification ── independent agent per finding (parallel, capped)
  Phase 4: Report ──────── handoff to Reporter (clean context)
"""

from __future__ import annotations

import json
import os
import sys
import asyncio
import time
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from agents import Agent, Runner, set_tracing_disabled
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from llm.tools import EXPANDED_TOOLS, set_quiet
from llm.schemas import (
    ReconOutput, EnumOutput, VulnOutput, VerifiedFinding,
    ScanReport, Finding,
)
from llm import evidence
from llm.rag import RAG_TOOLS

set_tracing_disabled(True)

# ─── Aesthetic constants ───────────────────────────────────────────
# Minimal palette — 4 colors only
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
RESET = "\033[0m"

# Creative signs (small, tasteful)
DIAMOND = "\u25c6"       # ◆ phase marker
ARROW = "\u25b8"         # ▸ phase start
CHECK = "\u2713"         # ✓ done
CROSS = "\u2717"         # ✗ failed
BAR = "\u2502"           # │ agent activity
TIMER = "\u23f1"         # ⏱ timing
ARROW_R = "\u2192"       # → result
DOT = "\u00b7"           # · separator


def _make_model(model_config: dict):
    model_name = model_config["name"]
    api_base = model_config.get("api_base")
    api_key = model_config.get("api_key") or "dummy"
    if "/" in model_name:
        model_name = model_name.split("/", 1)[1]
    client = AsyncOpenAI(base_url=api_base, api_key=api_key)
    return OpenAIChatCompletionsModel(model=model_name, openai_client=client)


# ─── Clean output helpers ──────────────────────────────────────────

def _line(msg: str = ""):
    """Print a line."""
    print(msg, flush=True)


def _phase(num: int, title: str, subtitle: str = ""):
    """Print a phase header."""
    sub = f" {DIM}{DOT} {subtitle}{RESET}" if subtitle else ""
    print(f"\n  {BOLD}{DIAMOND} phase {num}{RESET} {BOLD}{title}{RESET}{sub}", flush=True)


def _agent_activity(agent: str, tool: str, result: str, status: str = "ok"):
    """Print a single agent activity line."""
    icon = f"{GREEN}{CHECK}{RESET}" if status == "ok" else f"{RED}{CROSS}{RESET}" if status == "error" else f"{YELLOW}{ARROW_R}{RESET}"
    agent_padded = f"{agent:<10}"
    print(f"  {DIM}{BAR}{RESET} {BLUE}{agent_padded}{RESET} {DIM}{tool}{RESET} {ARROW_R} {result}", flush=True)


def _phase_done(title: str, elapsed: float, extra: str = ""):
    """Print phase completion."""
    extra_str = f" {DIM}{DOT}{RESET} {extra}" if extra else ""
    print(f"  {GREEN}{CHECK}{RESET} {title} {DIM}{TIMER} {elapsed:.1f}s{RESET}{extra_str}", flush=True)


def _phase_fail(title: str, elapsed: float, error: str):
    """Print phase failure."""
    print(f"  {RED}{CROSS}{RESET} {title} {DIM}{TIMER} {elapsed:.1f}s{RESET} {DIM}{DOT} {error}{RESET}", flush=True)


def _box(title: str, lines: list[str], color: str = MAGENTA):
    """Print a clean box with content."""
    width = max(len(title), max((len(l) for l in lines), default=0)) + 4
    print(f"\n  {color}{BOLD}\u256d{'\u2500' * width}\u256e{RESET}", flush=True)
    print(f"  {color}{BOLD}\u2502{RESET} {BOLD}{title}{' ' * (width - len(title) - 1)}{color}{BOLD}\u2502{RESET}", flush=True)
    for line in lines:
        print(f"  {color}{BOLD}\u2502{RESET} {line}{' ' * (width - len(line) - 1)}{color}{BOLD}\u2502{RESET}", flush=True)
    print(f"  {color}{BOLD}\u2570{'\u2500' * width}\u256f{RESET}", flush=True)


# ─── Agent system prompts ──────────────────────────────────────────

RECON_PROMPT = """You are the RECONNAISSANCE agent in a security scanning swarm.

Your job: Discover the attack surface of the target.
  1. run_dns_lookup(domain) — get DNS records (A, MX, TXT, NS)
  2. run_subfinder(domain) — find ALL subdomains
  3. run_httpx(target) — probe which hosts are live, get status + title + tech
  4. run_nmap(target) — scan top 100 ports on the main domain
  5. run_whatweb(target) — fingerprint technologies

Store ALL raw output using store_evidence() — keep only evidence_ids in your response.
DO NOT include raw tool output in your final answer — only structured data.

You MUST output a valid ReconOutput with:
  - subdomains: list of all discovered subdomains
  - live_hosts: list of {host, status, title, tech}
  - open_ports: list of {port, service, version}
  - technologies: list of detected technologies
  - summary: brief text summary
"""

ENUM_PROMPT = """You are the ENUMERATION agent in a security scanning swarm.

Your job: Find hidden paths, API endpoints, and sensitive files on the target.
  1. run_ffuf(url) — fuzz directories (use https://target/FUZZ)
  2. run_curl(url + "/robots.txt") — check robots.txt
  3. run_curl(url + "/.git/HEAD") — check for exposed git
  4. run_curl(url + "/.env") — check for exposed env
  5. run_curl(url + "/sitemap.xml") — check sitemap
  6. check_security_headers(url) — check missing security headers
  7. If WordPress detected, run_wpscan(target)

Store ALL raw output using store_evidence() — keep only evidence_ids.
DO NOT include raw tool output in your final answer.

You MUST output a valid EnumOutput with:
  - directories: list of {path, status, size}
  - api_endpoints: list of discovered API paths
  - sensitive_files: list of exposed sensitive files found
  - high_value_targets: targets that need deeper scanning
  - summary: brief text summary
"""

VULN_PROMPT = """You are the VULNERABILITY SCANNER agent in a security scanning swarm.

Your job: Scan for vulnerabilities using multiple tools.
  1. run_nuclei(target) — run nuclei templates
  2. run_nikto(target) — run Nikto web scanner
  3. run_sqlmap(url) — test for SQL injection on any params found
  4. search_cve(keyword) — look up CVEs for detected tech/versions
  5. search_exploits(query) — search for public exploits
  6. search_knowledge(query) — search the RAG knowledge base for relevant CWE/OWASP

For EACH vulnerability found, create a Finding with:
  - evidence_ref: the evidence_id from store_evidence()
  - discovery_commands: exact commands that found it
  - poc: a curl command to reproduce
  - cwe and owasp: proper classifications (use search_knowledge to find them)

Store ALL raw output using store_evidence() — keep only evidence_ids.
DO NOT report findings without evidence_ref — they will be rejected.

You MUST output a valid VulnOutput with findings list.
"""

VERIFY_PROMPT = """You are the VERIFIER agent — an independent fact-checker.

Your job: Independently verify a vulnerability finding by replaying its PoC.

For the finding you receive:
  1. Read the poc field — it's a curl command
  2. Run run_curl(url) to replay the exact request
  3. Compare the response to poc_expected_result
  4. If the finding is confirmed, set verified=True
  5. If it's a false positive, set false_positive=True
  6. Adjust severity if the impact is different than claimed

Be SKEPTICAL. You are the last line of defense against false positives.
A 404 page is NOT a vulnerability. A default page is NOT necessarily a vuln.

You MUST output a valid VerifiedFinding.
"""

REPORTER_PROMPT = """You are the REPORTER agent for a CERT-In vulnerability assessment.

Your job: Generate the final CERT-In report from verified findings ONLY.

Rules:
  - Only include findings where verified=True and false_positive=False
  - Assign CVSS 3.1 scores based on actual impact
  - Include CERT-In advisory references where applicable
  - Order vulnerabilities by severity (critical first)
  - Provide actionable remediation steps
  - Include all scan commands for reproducibility

You MUST output a valid ScanReport.
"""


# ─── Orchestrator ───────────────────────────────────────────────────

def _create_agents(model_config: dict):
    """Create all agents for the swarm."""
    model = _make_model(model_config)
    scan_tools = [t for t in EXPANDED_TOOLS if t.name not in ("read_file", "write_file")]

    recon_agent = Agent(
        name="Recon", instructions=RECON_PROMPT, model=model,
        tools=scan_tools + RAG_TOOLS, output_type=ReconOutput,
    )
    enum_agent = Agent(
        name="Enum", instructions=ENUM_PROMPT, model=model,
        tools=scan_tools, output_type=EnumOutput,
    )
    vuln_agent = Agent(
        name="VulnScan", instructions=VULN_PROMPT, model=model,
        tools=scan_tools + RAG_TOOLS, output_type=VulnOutput,
    )
    verify_agent = Agent(
        name="Verifier", instructions=VERIFY_PROMPT, model=model,
        tools=[t for t in scan_tools if t.name in ("run_curl", "fetch_evidence", "check_security_headers")],
        output_type=VerifiedFinding,
    )
    reporter_agent = Agent(
        name="Reporter", instructions=REPORTER_PROMPT, model=model,
        output_type=ScanReport,
    )
    return recon_agent, enum_agent, vuln_agent, verify_agent, reporter_agent


async def _run_phase(agent: Agent, prompt: str, max_turns: int = 25):
    """Run a single phase agent. Returns (output, elapsed)."""
    start = time.time()
    try:
        result = await Runner.run(agent, prompt, max_turns=max_turns)
        elapsed = time.time() - start
        return result.final_output, elapsed
    except Exception as e:
        elapsed = time.time() - start
        return None, elapsed


def _recon_summary(out: ReconOutput | None) -> str:
    if not out:
        return "failed"
    parts = []
    if out.subdomains:
        parts.append(f"{len(out.subdomains)} subdomains")
    if out.live_hosts:
        parts.append(f"{len(out.live_hosts)} live hosts")
    if out.open_ports:
        parts.append(f"{len(out.open_ports)} ports")
    if out.technologies:
        parts.append(f"{len(out.technologies)} tech")
    return f"found {', '.join(parts)}" if parts else "no results"


def _enum_summary(out: EnumOutput | None) -> str:
    if not out:
        return "failed"
    parts = []
    if out.directories:
        parts.append(f"{len(out.directories)} paths")
    if out.api_endpoints:
        parts.append(f"{len(out.api_endpoints)} API endpoints")
    if out.sensitive_files:
        parts.append(f"{len(out.sensitive_files)} sensitive files")
    return f"found {', '.join(parts)}" if parts else "no results"


def _vuln_summary(out: VulnOutput | None) -> str:
    if not out:
        return "failed"
    n = len(out.findings)
    if n == 0:
        return "no findings"
    by_sev = {}
    for f in out.findings:
        s = f.severity
        by_sev[s] = by_sev.get(s, 0) + 1
    sev_str = ", ".join(f"{v} {k}" for k, v in sorted(by_sev.items()))
    return f"{n} findings ({sev_str})"


async def _verify_finding(verify_agent: Agent, finding: Finding, semaphore: asyncio.Semaphore):
    """Verify a single finding using the Verifier agent."""
    async with semaphore:
        prompt = f"""Verify this finding by replaying its PoC:

Finding ID: {finding.id}
Title: {finding.title}
Severity: {finding.severity}
PoC: {finding.poc}
Expected Result: {finding.poc_expected_result}
Evidence ID: {finding.evidence_ref}

Run the PoC using run_curl and check if the expected result is observed.
"""
        result, elapsed = await _run_phase(verify_agent, prompt, max_turns=5)
        if result and isinstance(result, VerifiedFinding):
            result.finding_id = finding.id
            status = f"{GREEN}{CHECK} verified{RESET}" if result.verified and not result.false_positive else f"{RED}{CROSS} false positive{RESET}"
            print(f"  {DIM}{BAR}{RESET} {BLUE}{'verify':<10}{RESET} {DIM}{finding.id}{RESET} {ARROW_R} {status}", flush=True)
            return result
        print(f"  {DIM}{BAR}{RESET} {BLUE}{'verify':<10}{RESET} {DIM}{finding.id}{RESET} {ARROW_R} {YELLOW}{CROSS} verification failed{RESET}", flush=True)
        return VerifiedFinding(finding_id=finding.id, verified=False,
                               verification_output="Verification failed", false_positive=True)


async def run_swarm(target: str, model_config: dict, console=None) -> dict:
    """Run the full multi-agent security scan with clean output."""

    # Suppress individual tool prints — orchestrator handles all output
    set_quiet(True)

    # Initialize evidence DB
    Path("results").mkdir(parents=True, exist_ok=True)
    evidence.init_db("results/evidence.db")

    # Create agents
    recon_agent, enum_agent, vuln_agent, verify_agent, reporter_agent = _create_agents(model_config)

    # Header
    _box(
        f"{DIAMOND} CERT-In Swarm",
        [
            f"target  {DOT}  {target}",
            f"model   {DOT}  {model_config['name']}",
            f"agents  {DOT}  5 (recon {ARROW_R} enum {ARROW_R} vuln {ARROW_R} verify {ARROW_R} report)",
            f"tools   {DOT}  17 security + 6 RAG",
        ],
    )

    session_start = time.time()
    all_findings: list[Finding] = []

    # ─── Phase 1: Recon + Enum (PARALLEL) ─────────────────────────
    _phase(1, "recon + enumeration", "parallel")

    recon_prompt = f"Perform reconnaissance on: {target}\nStore all raw output with store_evidence(). Output ReconOutput."
    enum_prompt = f"Perform enumeration on: {target}\nStore all raw output with store_evidence(). Output EnumOutput."

    recon_result, enum_result = await asyncio.gather(
        _run_phase(recon_agent, recon_prompt, max_turns=25),
        _run_phase(enum_agent, enum_prompt, max_turns=25),
    )

    recon_out, recon_time = recon_result
    enum_out, enum_time = enum_result

    _phase_done("recon", recon_time, _recon_summary(recon_out))
    _phase_done("enum", enum_time, _enum_summary(enum_out))

    # ─── Phase 2: Vulnerability Scanning ──────────────────────────
    _phase(2, "vulnerability scanning")

    targets_to_scan = [target]
    if recon_out and hasattr(recon_out, "subdomains"):
        targets_to_scan.extend(recon_out.subdomains[:5])

    vuln_prompt = f"""Scan for vulnerabilities on these targets: {', '.join(targets_to_scan[:6])}

Recon summary: {recon_out.summary if recon_out else 'N/A'}
Enum summary: {enum_out.summary if enum_out else 'N/A'}

For each target:
1. run_nuclei(target)
2. run_nikto(target)
3. search_cve for any detected technologies
4. search_knowledge to classify findings with proper CWE/OWASP
5. Store ALL raw output with store_evidence()

Create a Finding for each vulnerability with evidence_ref pointing to stored evidence.
Output VulnOutput.
"""
    vuln_out, vuln_time = await _run_phase(vuln_agent, vuln_prompt, max_turns=35)

    if vuln_out and hasattr(vuln_out, "findings"):
        all_findings = vuln_out.findings

    _phase_done("vulnscan", vuln_time, _vuln_summary(vuln_out))

    # ─── Phase 3: Independent Verification ────────────────────────
    if all_findings:
        _phase(3, "verification", f"{len(all_findings)} findings, max 3 parallel")

        sem = asyncio.Semaphore(3)
        verification_tasks = [_verify_finding(verify_agent, f, sem) for f in all_findings]
        verification_results = await asyncio.gather(*verification_tasks)

        verified_count = sum(1 for v in verification_results if v.verified and not v.false_positive)
        fp_count = sum(1 for v in verification_results if v.false_positive)

        for f in all_findings:
            v = next((r for r in verification_results if r.finding_id == f.id), None)
            if v:
                f.verified = v.verified and not v.false_positive
                if v.adjusted_severity:
                    f.severity = v.adjusted_severity
                evidence.mark_verified(f.id, f.verified)

        verify_time = time.time() - session_start
        _phase_done("verification", verify_time, f"{verified_count} verified, {fp_count} filtered")
    else:
        _phase(3, "verification", "no findings to verify")
        print(f"  {DIM}{BAR} nothing to verify{RESET}", flush=True)
        verified_count = 0

    # ─── Phase 4: Report Generation ───────────────────────────────
    _phase(4, "report generation")

    verified_findings = [f for f in all_findings if f.verified]

    report_prompt = f"""Generate the CERT-In report for target: {target}

Verified findings ({len(verified_findings)}):
{json.dumps([f.model_dump() for f in verified_findings], indent=2, default=str)}

All scan commands used: check evidence store summary.
Targets scanned: {targets_to_scan}

Only include VERIFIED findings (verified=True, false_positive=False).
Output ScanReport.
"""
    report_out, report_time = await _run_phase(reporter_agent, report_prompt, max_turns=15)

    if report_out and isinstance(report_out, ScanReport):
        _phase_done("report", report_time, "generated")
    else:
        _phase_done("report", report_time, "fallback (no structured output)")

    # ─── Summary ──────────────────────────────────────────────────
    total_time = time.time() - session_start
    ev_summary = evidence.summary()

    summary_lines = []
    if report_out and isinstance(report_out, ScanReport):
        # Save report
        report_path = Path("results") / "cert-in-report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_out.model_dump_json(indent=2))

        vulns = report_out.vulnerabilities
        summary = report_out.vulnerability_summary

        summary_lines.append(f"findings {DOT}  {summary.get('critical', 0)} critical, {summary.get('high', 0)} high, {summary.get('medium', 0)} medium, {summary.get('low', 0)} low")
        summary_lines.append(f"verified {DOT}  {len(verified_findings)} of {len(all_findings)} passed verification")
        summary_lines.append(f"evidence {DOT}  {ev_summary['total_evidence']} items stored in SQLite")
        summary_lines.append(f"report   {DOT}  results/cert-in-report.json")
        summary_lines.append(f"time     {DOT}  {total_time:.1f}s total")

        _box(
            f"{CHECK} complete {DOT} {len(vulns)} verified findings",
            summary_lines,
            GREEN,
        )

        # List findings
        if vulns:
            print(f"\n  {BOLD}Findings:{RESET}", flush=True)
            for i, v in enumerate(vulns, 1):
                sev = v.severity.upper()
                color = RED if sev == "CRITICAL" else YELLOW if sev in ("HIGH", "MEDIUM") else GREEN
                print(f"  {color}{BOLD}[{i}]{RESET} {v.title} {DIM}({sev} {DOT} CVSS {v.cvss_score} {DOT} {v.cwe or 'no CWE'}){RESET}", flush=True)

        return {"status": "success", "report": report_out.model_dump(), "findings": len(verified_findings)}

    # Fallback if no structured report
    summary_lines.append(f"verified {DOT}  {len(verified_findings)} of {len(all_findings)} passed")
    summary_lines.append(f"evidence {DOT}  {ev_summary['total_evidence']} items stored")
    summary_lines.append(f"time     {DOT}  {total_time:.1f}s total")

    _box(f"{CHECK} complete", summary_lines, GREEN)

    return {"status": "completed", "report": None, "findings": len(verified_findings)}


def run_swarm_sync(target: str, model_config: dict, console=None) -> dict:
    """Synchronous wrapper for the async swarm."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    return asyncio.run(run_swarm(target, model_config, console))
