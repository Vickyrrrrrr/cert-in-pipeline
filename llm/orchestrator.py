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

import warnings
warnings.filterwarnings("ignore")

import json
import os
import sys
import asyncio
import time
import threading
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
from llm.interface import supports_structured_output

set_tracing_disabled(True)

# Local print lock for spinner (don't import from tools — avoid circular deps)
_print_lock = threading.Lock()

# Heartbeat spinner — runs continuously, cleared when tools print
_heartbeat_stop = None
_heartbeat_thread = None
_heartbeat_active = False


def _start_heartbeat():
    """Start the Argus watching spinner in background."""
    global _heartbeat_stop, _heartbeat_thread, _heartbeat_active
    _heartbeat_stop = threading.Event()
    _heartbeat_active = True

    spinner = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"
    start = time.time()

    def _spin():
        i = 0
        while not _heartbeat_stop.wait(0.15):
            elapsed = int(time.time() - start)
            with _print_lock:
                sys.stdout.write(f"\r  {DIM}{spinner[i % len(spinner)]} Argus watching... ({elapsed}s){RESET}   ")
                sys.stdout.flush()
            i += 1

    _heartbeat_thread = threading.Thread(target=_spin, daemon=True)
    _heartbeat_thread.start()


def _stop_heartbeat():
    """Stop the spinner and clear the line."""
    global _heartbeat_stop, _heartbeat_thread, _heartbeat_active
    if _heartbeat_stop:
        _heartbeat_stop.set()
    if _heartbeat_thread:
        _heartbeat_thread.join(timeout=1)
    _heartbeat_active = False
    with _print_lock:
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()

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
    failed = "failed" in extra or "no results" in extra
    icon = f"{RED}{CROSS}{RESET}" if failed else f"{GREEN}{CHECK}{RESET}"
    print(f"  {icon} {title} {DIM}{TIMER} {elapsed:.1f}s{RESET}{extra_str}", flush=True)


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

After running all tools, output a JSON object with this exact structure:
{
  "subdomains": ["sub1.example.com", "sub2.example.com"],
  "live_hosts": [{"host": "...", "status": 200, "title": "...", "tech": ["..."]}],
  "open_ports": [{"port": 80, "service": "http", "version": "..."}],
  "technologies": ["Apache", "WordPress"],
  "dns_records": [{"type": "A", "value": "1.2.3.4"}],
  "summary": "Brief text summary of attack surface"
}
Output ONLY the JSON, no other text.
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

After running all tools, output a JSON object with this exact structure:
{
  "directories": [{"path": "/admin", "status": 200, "size": 1234}],
  "api_endpoints": ["/api/v1/users", "/api/v2/products"],
  "sensitive_files": [".git/HEAD", ".env"],
  "high_value_targets": ["admin.example.com", "api.example.com"],
  "summary": "Brief text summary of enumeration findings"
}
Output ONLY the JSON, no other text.
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

After running all tools, output a JSON object with this exact structure:
{
  "findings": [
    {
      "id": "F-001",
      "title": "Exposed Admin Panel",
      "severity": "high",
      "cwe": "CWE-284",
      "owasp": "A01",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "affected_component": "https://target/admin",
      "description": "Admin panel accessible without auth",
      "impact": "Attacker can access admin functions",
      "evidence_ref": "ev_abc123",
      "discovery_method": "ffuf directory scan",
      "discovery_commands": ["ffuf -u https://target/FUZZ -w common.txt"],
      "poc": "curl -s https://target/admin",
      "poc_expected_result": "HTTP 200 with admin login page",
      "remediation": "Restrict admin panel to VPN or IP allowlist",
      "verified": false
    }
  ],
  "templates_run": 5000,
  "summary": "Brief summary of scan results"
}
Output ONLY the JSON, no other text.
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

After verifying, output a JSON object with this exact structure:
{
  "finding_id": "F-001",
  "verified": true,
  "verification_output": "HTTP 200 confirmed, admin panel visible",
  "false_positive": false,
  "adjusted_severity": null
}
Output ONLY the JSON, no other text.
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

Output a JSON object with this exact structure:
{
  "target": "example.com",
  "scan_timestamp": "2025-01-01T00:00:00",
  "executive_summary": "Brief summary for management",
  "targets_scanned": ["example.com", "sub.example.com"],
  "scan_commands_used": ["nmap -sV target", "nuclei -u target"],
  "vulnerability_summary": {"critical": 1, "high": 2, "medium": 3, "low": 1, "total": 7},
  "vulnerabilities": [
    {
      "id": "F-001",
      "title": "Exposed Admin Panel",
      "severity": "high",
      "cwe": "CWE-284",
      "owasp": "A01",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/...",
      "affected_component": "https://target/admin",
      "description": "...",
      "impact": "...",
      "evidence_ref": "ev_123",
      "discovery_method": "...",
      "discovery_commands": ["..."],
      "poc": "curl ...",
      "poc_expected_result": "...",
      "remediation": "...",
      "verified": true
    }
  ],
  "remediation_priority": ["Fix 1", "Fix 2"],
  "cert_in_references": ["CERT-In advisory reference"]
}
Output ONLY the JSON, no other text.
"""


# ─── Orchestrator ───────────────────────────────────────────────────

def _create_agents(model_config: dict, provider_name: str = ""):
    """Create all agents for the swarm.

    Provider-aware: if the provider supports response_format + tools (OpenAI, GLM,
    Anthropic, DeepSeek), we use Pydantic output_type on ALL agents (full hallucination
    guard). If not (Groq, Ollama), output_type is only on the Reporter (no tools),
    and tool-using agents get JSON format instructions in their prompt.

    Tool count is minimized per agent — Groq struggles with 20+ tools.
    """
    model = _make_model(model_config)
    all_tools = {t.name: t for t in EXPANDED_TOOLS}
    rag_tools = {t.name: t for t in RAG_TOOLS}

    # Each agent gets only the tools it needs (keeps tool schema small for Groq)
    recon_tool_names = ["run_subfinder", "run_nmap", "run_httpx", "run_whatweb", "run_dns_lookup", "store_evidence"]
    enum_tool_names = ["run_ffuf", "run_curl", "check_security_headers", "run_wpscan", "store_evidence"]
    vuln_tool_names = ["run_nuclei", "run_nikto", "run_sqlmap", "search_cve", "search_exploits", "search_knowledge", "store_evidence"]
    verify_tool_names = ["run_curl", "fetch_evidence", "check_security_headers"]

    recon_tools = [all_tools[n] for n in recon_tool_names if n in all_tools]
    enum_tools = [all_tools[n] for n in enum_tool_names if n in all_tools]
    vuln_tools = [all_tools[n] for n in vuln_tool_names if n in all_tools] + [rag_tools["search_cve"], rag_tools["search_exploits"], rag_tools["search_knowledge"]]
    verify_tools = [all_tools[n] for n in verify_tool_names if n in all_tools]

    structured = supports_structured_output(provider_name)

    recon_agent = Agent(
        name="Recon", instructions=RECON_PROMPT, model=model,
        tools=recon_tools,
        **({"output_type": ReconOutput} if structured else {}),
    )
    enum_agent = Agent(
        name="Enum", instructions=ENUM_PROMPT, model=model,
        tools=enum_tools,
        **({"output_type": EnumOutput} if structured else {}),
    )
    vuln_agent = Agent(
        name="VulnScan", instructions=VULN_PROMPT, model=model,
        tools=vuln_tools,
        **({"output_type": VulnOutput} if structured else {}),
    )
    verify_agent = Agent(
        name="Verifier", instructions=VERIFY_PROMPT, model=model,
        tools=verify_tools,
        **({"output_type": VerifiedFinding} if structured else {}),
    )
    reporter_agent = Agent(
        name="Reporter", instructions=REPORTER_PROMPT, model=model,
        **({"output_type": ScanReport} if structured else {}),
    )
    return recon_agent, enum_agent, vuln_agent, verify_agent, reporter_agent


def _parse_output(raw, model_class):
    """Parse agent output into Pydantic model (handles text, markdown, truncated JSON)."""
    if raw is None:
        return None
    if isinstance(raw, model_class):
        return raw
    if isinstance(raw, str):
        import re
        text = raw.strip()

        # Extract JSON from markdown code blocks
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    result = _try_parse_json(part, model_class)
                    if result:
                        return result

        # Try parsing as JSON directly
        result = _try_parse_json(text, model_class)
        if result:
            return result

        # Try extracting the largest JSON object
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            result = _try_parse_json(json_match.group(0), model_class)
            if result:
                return result
    return None


def _try_parse_json(json_str: str, model_class) -> object | None:
    """Try to parse JSON, auto-closing truncated JSON if needed."""
    import re

    # Try as-is first
    try:
        return model_class.model_validate_json(json_str)
    except Exception:
        pass

    # Try progressively smaller substrings
    for i in range(len(json_str), 10, -1):
        try:
            return model_class.model_validate_json(json_str[:i])
        except Exception:
            continue

    # Try auto-closing truncated JSON (add missing brackets/braces)
    truncated = json_str.strip().rstrip('"').rstrip(',').rstrip()
    open_braces = truncated.count('{') - truncated.count('}')
    open_brackets = truncated.count('[') - truncated.count(']')
    closed = truncated + ('}' * max(0, open_braces)) + (']' * max(0, open_brackets))
    try:
        return model_class.model_validate_json(closed)
    except Exception:
        pass

    return None


async def _run_phase(agent: Agent, prompt: str, max_turns: int = 25, label: str = ""):
    """Run a single phase agent with a live spinner. Returns (output, elapsed)."""
    stop_event = threading.Event()
    spinner = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"
    start = time.time()

    def _spin():
        i = 0
        while not stop_event.wait(0.15):
            elapsed = int(time.time() - start)
            with _print_lock:
                sys.stdout.write(f"\r  {DIM}{spinner[i % len(spinner)]} {label}... ({elapsed}s){RESET}   ")
                sys.stdout.flush()
            i += 1

    spin_thread = threading.Thread(target=_spin, daemon=True)
    spin_thread.start()

    try:
        result = await Runner.run(agent, prompt, max_turns=max_turns)
        elapsed = time.time() - start
        stop_event.set()
        spin_thread.join(timeout=1)
        _clear_spinner()
        return result.final_output, elapsed
    except Exception as e:
        elapsed = time.time() - start
        stop_event.set()
        spin_thread.join(timeout=1)
        _clear_spinner()
        err = str(e)[:200]
        print(f"  {RED}{CROSS} error: {err}{RESET}", flush=True)
        return None, elapsed


def _clear_spinner():
    with _print_lock:
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()


async def _run_parallel(phases: list[tuple[Agent, str, int, str]], phase_label: str = "scanning"):
    """Run multiple phases in parallel. If phase_label is empty, no spinner (tool output shows progress)."""
    use_spinner = bool(phase_label)
    stop_event = threading.Event()
    spinner = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"
    start = time.time()

    def _spin():
        i = 0
        while not stop_event.wait(0.15):
            elapsed = int(time.time() - start)
            with _print_lock:
                sys.stdout.write(f"\r  {DIM}{spinner[i % len(spinner)]} {phase_label}... ({elapsed}s){RESET}   ")
                sys.stdout.flush()
            i += 1

    if use_spinner:
        spin_thread = threading.Thread(target=_spin, daemon=True)
        spin_thread.start()

    tasks = [_run_phase_silent(agent, prompt, max_turns) for agent, prompt, max_turns, _ in phases]
    results = await asyncio.gather(*tasks)

    if use_spinner:
        stop_event.set()
        spin_thread.join(timeout=1)
        _clear_spinner()

    elapsed = time.time() - start
    labels = [label for _, _, _, label in phases]
    return results, elapsed, labels


async def _run_phase_silent(agent: Agent, prompt: str, max_turns: int):
    """Run agent without spinner (used in parallel mode). Returns (output, elapsed)."""
    start = time.time()
    try:
        result = await Runner.run(agent, prompt, max_turns=max_turns)
        return result.final_output, time.time() - start
    except Exception as e:
        elapsed = time.time() - start
        err = str(e)[:300]
        print(f"  {RED}{CROSS} error: {err}{RESET}", flush=True)
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


async def _verify_finding(verify_agent: Agent, finding: Finding, semaphore: asyncio.Semaphore, structured: bool = True):
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
        result, elapsed = await _run_phase(verify_agent, prompt, max_turns=5, label=f"verifying {finding.id}")
        if not structured and result:
            result = _parse_output(result, VerifiedFinding)
        if result and isinstance(result, VerifiedFinding):
            result.finding_id = finding.id
            status = f"{GREEN}{CHECK} verified{RESET}" if result.verified and not result.false_positive else f"{RED}{CROSS} false positive{RESET}"
            print(f"  {DIM}{BAR}{RESET} {BLUE}{'verify':<10}{RESET} {DIM}{finding.id}{RESET} {ARROW_R} {status}", flush=True)
            return result
        print(f"  {DIM}{BAR}{RESET} {BLUE}{'verify':<10}{RESET} {DIM}{finding.id}{RESET} {ARROW_R} {YELLOW}{CROSS} verification failed{RESET}", flush=True)
        return VerifiedFinding(finding_id=finding.id, verified=False,
                               verification_output="Verification failed", false_positive=True)


async def run_swarm(target: str, model_config: dict, console=None, provider_name: str = "") -> dict:
    """Run the full multi-agent security scan with clean output."""

    # Don't suppress tool output — user wants to see both agents working.
    # _print_lock in tools.py ensures each line is atomic (no garbled output).
    set_quiet(False)

    # Initialize evidence DB
    Path("results").mkdir(parents=True, exist_ok=True)
    evidence.init_db("results/evidence.db")

    # Create agents (provider-aware: structured output if supported)
    recon_agent, enum_agent, vuln_agent, verify_agent, reporter_agent = _create_agents(model_config, provider_name)

    structured = supports_structured_output(provider_name)
    mode_label = "structured (Pydantic)" if structured else "fallback (JSON prompt)"

    # Header
    _box(
        f"{DIAMOND} Argus",
        [
            f"target  {DOT}  {target}",
            f"model   {DOT}  {model_config['name']}",
            f"agents  {DOT}  5 eyes (recon {ARROW_R} enum {ARROW_R} vuln {ARROW_R} verify {ARROW_R} report)",
            f"tools   {DOT}  17 security + 6 RAG",
            f"mode    {DOT}  {mode_label}",
        ],
    )

    session_start = time.time()
    all_findings: list[Finding] = []

    # ─── Phase 1: Recon + Enum (PARALLEL) ─────────────────────────
    _phase(1, "recon + enumeration", "parallel")

    recon_prompt = f"Perform reconnaissance on: {target}\nStore all raw output with store_evidence(). Output ReconOutput."
    enum_prompt = f"Perform enumeration on: {target}\nStore all raw output with store_evidence(). Output EnumOutput."

    # Run in parallel — heartbeat spinner + tool output both visible
    _start_heartbeat()
    (recon_result, enum_result), phase1_time, _ = await _run_parallel(
        [
            (recon_agent, recon_prompt, 25, "recon"),
            (enum_agent, enum_prompt, 25, "enum"),
        ],
        phase_label="",
    )
    _stop_heartbeat()

    recon_out, recon_time = recon_result
    enum_out, enum_time = enum_result

    # Parse fallback text output if not using structured output_type
    if not structured:
        recon_out = _parse_output(recon_out, ReconOutput)
        enum_out = _parse_output(enum_out, EnumOutput)

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
    _start_heartbeat()
    vuln_out, vuln_time = await _run_phase(vuln_agent, vuln_prompt, max_turns=35, label="")
    _stop_heartbeat()

    if not structured:
        vuln_out = _parse_output(vuln_out, VulnOutput)

    if vuln_out and hasattr(vuln_out, "findings"):
        all_findings = vuln_out.findings

    _phase_done("vulnscan", vuln_time, _vuln_summary(vuln_out))

    # ─── Phase 3: Independent Verification ────────────────────────
    if all_findings:
        _phase(3, "verification", f"{len(all_findings)} findings")

        sem = asyncio.Semaphore(1)  # serial verification — avoids GLM rate limits
        verification_tasks = [_verify_finding(verify_agent, f, sem, structured) for f in all_findings]
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
    report_out, report_time = await _run_phase(reporter_agent, report_prompt, max_turns=15, label="generating report")

    if not structured and report_out:
        report_out = _parse_output(report_out, ScanReport)

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
            print(f"\n  {BOLD}Argus eyes found:{RESET}", flush=True)
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

    # Close Qdrant client gracefully (suppress shutdown warning)
    try:
        from llm.rag import _get_client
        client = _get_client()
        if client:
            client.close()
    except Exception:
        pass

    return {"status": "completed", "report": None, "findings": len(verified_findings)}


def run_swarm_sync(target: str, model_config: dict, console=None, provider_name: str = "") -> dict:
    """Synchronous wrapper for the async swarm."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    return asyncio.run(run_swarm(target, model_config, console, provider_name))
