"""Multi-Agent Security Orchestrator — the swarm.

Architecture (based on MAPTA, xOffense, PentestAgent research):

  ┌─────────────┐
  │ Coordinator │  ← owns the scan, calls phase agents as tools
  └──────┬──────┘
         │ asyncio.gather (recon + enum run in parallel)
    ┌────┼────┐
    ▼    ▼    ▼
  Recon  Enum  Vuln   ← specialized agents, each with own context + tools
    │    │    │
    └────┼────┘
         ▼
  ┌──────────┐
  │ Verifier │  ← independent agent, replays each finding's PoC
  └────┬─────┘
       │ only verified findings pass
       ▼
  ┌──────────┐
  │ Reporter │  ← handoff, fresh context, generates final CERT-In report
  └──────────┘

Key design decisions:
  1. Coordinator calls phase agents as tools (agents-as-tools pattern)
  2. Recon + Enum run in parallel via asyncio.gather (independent)
  3. Vuln runs AFTER (depends on enum output)
  4. Each finding gets independently verified by a fresh Verifier agent
  5. Reporter gets a handoff with filtered context (no raw tool output)
  6. Every agent has a Pydantic output_type — no free-text hallucination
  7. Raw tool output stored in evidence DB, only IDs exchanged
"""

from __future__ import annotations

import json
import os
import sys
import asyncio
import threading
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

from llm.tools import EXPANDED_TOOLS, _safe_print, _tool_call, _tool_result, _clear_line, _thinking
from llm.schemas import (
    ReconOutput, EnumOutput, VulnOutput, VerifiedFinding,
    ScanReport, CoordinatorHandoff, Finding,
)
from llm import evidence
from llm.rag import RAG_TOOLS

set_tracing_disabled(True)

BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
RESET = "\033[0m"


def _make_model(model_config: dict):
    """Create an OpenAI-compatible model from config."""
    model_name = model_config["name"]
    api_base = model_config.get("api_base")
    api_key = model_config.get("api_key") or "dummy"
    if "/" in model_name:
        model_name = model_name.split("/", 1)[1]
    client = AsyncOpenAI(base_url=api_base, api_key=api_key)
    return OpenAIChatCompletionsModel(model=model_name, openai_client=client)


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
  5. lookup_exploit(query) — search for public exploits

For EACH vulnerability found, create a Finding with:
  - evidence_ref: the evidence_id from store_evidence()
  - discovery_commands: exact commands that found it
  - poc: a curl command to reproduce
  - cwe and owasp: proper classifications (use lookup_cwe and lookup_owasp)

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
    scan_tools = [t for t in EXPANDED_TOOLS if t.__name__ not in ("read_file", "write_file")]

    recon_agent = Agent(
        name="Recon",
        instructions=RECON_PROMPT,
        model=model,
        tools=scan_tools + RAG_TOOLS,
        output_type=ReconOutput,
    )

    enum_agent = Agent(
        name="Enum",
        instructions=ENUM_PROMPT,
        model=model,
        tools=scan_tools,
        output_type=EnumOutput,
    )

    vuln_agent = Agent(
        name="VulnScan",
        instructions=VULN_PROMPT,
        model=model,
        tools=scan_tools + RAG_TOOLS,
        output_type=VulnOutput,
    )

    verify_agent = Agent(
        name="Verifier",
        instructions=VERIFY_PROMPT,
        model=model,
        tools=[t for t in scan_tools if t.__name__ in ("run_curl", "fetch_evidence", "check_security_headers")],
        output_type=VerifiedFinding,
    )

    reporter_agent = Agent(
        name="Reporter",
        instructions=REPORTER_PROMPT,
        model=model,
        output_type=ScanReport,
    )

    return recon_agent, enum_agent, vuln_agent, verify_agent, reporter_agent


async def _run_phase(agent: Agent, prompt: str, phase_name: str, max_turns: int = 25):
    """Run a single phase agent with nice output."""
    _safe_print(f"\n  {BLUE}{BOLD}{'─'*50}{RESET}")
    _safe_print(f"  {BLUE}{BOLD}▶ {phase_name} Agent{RESET}")
    _safe_print(f"  {BLUE}{'─'*50}{RESET}")

    start = time.time()
    try:
        result = await Runner.run(agent, prompt, max_turns=max_turns)
        elapsed = time.time() - start
        _safe_print(f"  {GREEN}✓ {phase_name} completed ({elapsed:.1f}s){RESET}")
        return result.final_output
    except Exception as e:
        elapsed = time.time() - start
        _safe_print(f"  {RED}✗ {phase_name} failed ({elapsed:.1f}s): {e}{RESET}")
        return None


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
        result = await _run_phase(verify_agent, prompt, f"Verify-{finding.id}", max_turns=5)
        if result and isinstance(result, VerifiedFinding):
            result.finding_id = finding.id
            return result
        return VerifiedFinding(finding_id=finding.id, verified=False,
                               verification_output="Verification failed", false_positive=True)


async def run_swarm(target: str, model_config: dict, console=None) -> dict:
    """Run the full multi-agent security scan."""

    # Initialize evidence DB
    Path("results").mkdir(parents=True, exist_ok=True)
    evidence.init_db("results/evidence.db")

    # Create agents
    recon_agent, enum_agent, vuln_agent, verify_agent, reporter_agent = _create_agents(model_config)

    # Header
    print(f"\n{BOLD}{MAGENTA}╭{'─'*60}╮{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {BOLD}Multi-Agent Security Swarm{RESET}{' '*(35)}{BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}├{'─'*60}┤{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Target:{RESET}  {target:<50} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Model:{RESET}   {model_config['name']:<50} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Agents:{RESET}  Coordinator → Recon + Enum → Vuln → Verify → Report{' '*(8)}{BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Tools:{RESET}   17 tools + 4 RAG tools{' '*(33)}{BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}╰{'─'*60}╯{RESET}", flush=True)
    print(f"\n{DIM}  ▶ = phase start    ✓ = completed    ✗ = failed{RESET}", flush=True)

    session_start = time.time()

    # ─── Phase 1: Recon + Enum in PARALLEL ────────────────────────
    print(f"\n  {BOLD}{CYAN}═══ PHASE 1: Recon + Enumeration (parallel) ═══{RESET}", flush=True)

    recon_prompt = f"Perform reconnaissance on: {target}\nStore all raw output with store_evidence(). Output ReconOutput."
    enum_prompt = f"Perform enumeration on: {target}\nStore all raw output with store_evidence(). Output EnumOutput."

    recon_result, enum_result = await asyncio.gather(
        _run_phase(recon_agent, recon_prompt, "Recon"),
        _run_phase(enum_agent, enum_prompt, "Enum"),
    )

    # ─── Phase 2: Vulnerability Scanning (sequential, depends on recon) ─
    print(f"\n  {BOLD}{CYAN}═══ PHASE 2: Vulnerability Scanning ═══{RESET}", flush=True)

    targets_to_scan = [target]
    if recon_result and hasattr(recon_result, 'subdomains'):
        targets_to_scan.extend(recon_result.subdomains[:5])

    vuln_prompt = f"""Scan for vulnerabilities on these targets: {', '.join(targets_to_scan[:6])}

Recon summary: {recon_result.summary if recon_result else 'N/A'}
Enum summary: {enum_result.summary if enum_result else 'N/A'}

For each target:
1. run_nuclei(target)
2. run_nikto(target)
3. search_cve for any detected technologies
4. Store ALL raw output with store_evidence()

Create a Finding for each vulnerability with evidence_ref pointing to stored evidence.
Output VulnOutput.
"""
    vuln_result = await _run_phase(vuln_agent, vuln_prompt, "VulnScan", max_turns=35)

    # ─── Phase 3: Verification (parallel, one verifier per finding) ──
    print(f"\n  {BOLD}{CYAN}═══ PHASE 3: Independent Verification ═══{RESET}", flush=True)

    all_findings = []
    if vuln_result and hasattr(vuln_result, 'findings'):
        all_findings = vuln_result.findings

    if all_findings:
        print(f"\n  {DIM}Verifying {len(all_findings)} findings (max 3 parallel)...{RESET}", flush=True)
        sem = asyncio.Semaphore(3)
        verification_tasks = [
            _verify_finding(verify_agent, f, sem) for f in all_findings
        ]
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

        print(f"\n  {GREEN}✓ Verified: {verified_count}{RESET}  {RED}False positives filtered: {fp_count}{RESET}", flush=True)
    else:
        print(f"\n  {YELLOW}No findings to verify{RESET}", flush=True)

    # ─── Phase 4: Report Generation (handoff to Reporter) ──────────
    print(f"\n  {BOLD}{CYAN}═══ PHASE 4: Report Generation ═══{RESET}", flush=True)

    verified_findings = [f for f in all_findings if f.verified]

    report_prompt = f"""Generate the CERT-In report for target: {target}

Verified findings ({len(verified_findings)}):
{json.dumps([f.model_dump() for f in verified_findings], indent=2, default=str)}

All scan commands used: check evidence store summary.
Targets scanned: {targets_to_scan}

Only include VERIFIED findings (verified=True, false_positive=False).
Output ScanReport.
"""
    report_result = await _run_phase(reporter_agent, report_prompt, "Reporter", max_turns=15)

    # ─── Summary ───────────────────────────────────────────────────
    total_time = time.time() - session_start
    ev_summary = evidence.summary()

    print(f"\n{BOLD}{GREEN}╭{'─'*60}╮{RESET}", flush=True)
    print(f"{BOLD}{GREEN}│{RESET} {BOLD}Swarm Scan Complete{RESET}{' '*(38)}{BOLD}{GREEN}│{RESET}", flush=True)
    print(f"{BOLD}{GREEN}├{'─'*60}┤{RESET}", flush=True)
    print(f"{BOLD}{GREEN}│{RESET} {DIM}Total time:{RESET}    {total_time:.1f}s{' '*(43)}{BOLD}{GREEN}│{RESET}", flush=True)
    print(f"{BOLD}{GREEN}│{RESET} {DIM}Findings:{RESET}      {len(all_findings)} total → {len(verified_findings)} verified{' '*(26)}{BOLD}{GREEN}│{RESET}", flush=True)
    print(f"{BOLD}{GREEN}│{RESET} {DIM}Evidence:{RESET}      {ev_summary['total_evidence']} items stored{' '*(32)}{BOLD}{GREEN}│{RESET}", flush=True)
    print(f"{BOLD}{GREEN}│{RESET} {DIM}False positives:{RESET} filtered by Verifier{' '*(31)}{BOLD}{GREEN}│{RESET}", flush=True)
    print(f"{BOLD}{GREEN}╰{'─'*60}╯{RESET}", flush=True)

    if report_result and isinstance(report_result, ScanReport):
        # Save report
        report_path = Path("results") / "cert-in-report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_result.model_dump_json(indent=2))

        vulns = report_result.vulnerabilities
        summary = report_result.vulnerability_summary

        print(f"\n{BOLD}Vulnerability Summary:{RESET}", flush=True)
        print(f"  {RED}Critical:{RESET} {summary.get('critical', 0)}", flush=True)
        print(f"  {YELLOW}High:{RESET}     {summary.get('high', 0)}", flush=True)
        print(f"  {YELLOW}Medium:{RESET}   {summary.get('medium', 0)}", flush=True)
        print(f"  {GREEN}Low:{RESET}      {summary.get('low', 0)}", flush=True)
        print(f"  {BOLD}Total:{RESET}     {len(vulns)}", flush=True)

        for i, v in enumerate(vulns, 1):
            sev = v.severity.upper()
            color = RED if sev == "CRITICAL" else YELLOW if sev in ("HIGH", "MEDIUM") else GREEN
            print(f"\n  {color}{BOLD}[{i}]{RESET} {v.title} {DIM}({sev}, CVSS: {v.cvss_score}){RESET}", flush=True)

        print(f"\n{GREEN}Report:{RESET}    results/cert-in-report.json", flush=True)
        print(f"{GREEN}Evidence:{RESET}  results/evidence.db", flush=True)

        return {"status": "success", "report": report_result.model_dump(), "findings": len(verified_findings)}

    return {"status": "completed", "report": None, "findings": len(verified_findings)}


def run_swarm_sync(target: str, model_config: dict, console=None) -> dict:
    """Synchronous wrapper for the async swarm."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    return asyncio.run(run_swarm(target, model_config, console))
