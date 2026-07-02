"""Merged agent — combines live mode (skills) + agent mode (tool execution).

The LLM reads skill instructions on-demand, runs tools, and analyzes results
per the skill's success criteria. Like Claude Code but for security scanning.
"""

import json
import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime

from agents import Agent, Runner, set_tracing_disabled
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from llm.tools import SECURITY_TOOLS, _normalize_url, _normalize_domain, _tool_call, _tool_result, _tool_running

set_tracing_disabled(True)

BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RESET = "\033[0m"

SKILLS_DIR = Path(__file__).parent.parent / "skills"

# Global flag — tools set this to False while running, True when LLM is thinking
_thinking = True


def _heartbeat(stop_event):
    """Print a heartbeat every 5 seconds while LLM is thinking."""
    import llm.tools as tools_mod
    spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    start = time.time()
    while not stop_event.wait(0.1):
        if tools_mod._thinking:
            elapsed = int(time.time() - start)
            sys.stdout.write(f"\r  {DIM}{spinner[i % len(spinner)]} Thinking... ({elapsed}s){RESET}    ")
            sys.stdout.flush()
            i += 1
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()


def _load_skill(name: str) -> str:
    """Load a skill MD file."""
    skill_path = SKILLS_DIR / name / "SKILL.md"
    if not skill_path.exists():
        return f"Skill '{name}' not found."
    return skill_path.read_text(encoding="utf-8")


def create_merged_agent(model_config: dict) -> Agent:
    """Create a merged agent that uses both skills and tools."""

    model_name = model_config["name"]
    api_base = model_config.get("api_base")
    api_key = model_config.get("api_key") or "dummy"

    if "/" in model_name:
        model_name = model_name.split("/", 1)[1]

    client = AsyncOpenAI(base_url=api_base, api_key=api_key)
    model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

    # Load key instructions from skills (condensed)
    recon_skill = _load_skill("01-recon")
    enum_skill = _load_skill("02-enumeration")
    port_skill = _load_skill("03-port-scan")
    vuln_skill = _load_skill("04-vuln-scan")
    analysis_skill = _load_skill("05-analysis")
    severity_skill = _load_skill("06-severity")
    exploit_skill = _load_skill("07-exploitability")
    report_skill = _load_skill("08-report")
    remediation_skill = _load_skill("09-remediation")

    system_prompt = f"""You are an expert security analyst performing a comprehensive vulnerability assessment.

You have access to security tools (run_httpx, run_nmap, run_nuclei, run_subfinder, run_ffuf, run_curl, run_sqlmap, write_file).

Follow this workflow EXACTLY:

## Phase 1: Reconnaissance
Run run_httpx on the target. Then analyze using these guidelines:
{recon_skill[:1500]}

## Phase 2: Enumeration
Run run_subfinder on the domain. Then analyze using these guidelines:
{enum_skill[:1500]}

## Phase 3: Port Scanning
Run run_nmap on the target. Then analyze using these guidelines:
{port_skill[:1500]}

## Phase 4: Vulnerability Scanning
Run run_nuclei on the target. Then classify findings using these guidelines:
{vuln_skill[:1500]}

## Phase 5: Verification
For each finding, verify if it's a TRUE POSITIVE or FALSE POSITIVE:
{analysis_skill[:1500]}

## Phase 6: Severity Scoring
Assign CVSS 3.1 scores to confirmed vulnerabilities:
{severity_skill[:1000]}

## Phase 7: Exploitability
Assess real-world exploitability:
{exploit_skill[:1000]}

## Phase 8: Report
Generate a CERT-In compliant report and save it using write_file:
{report_skill[:1500]}

## Phase 9: Remediation
Provide specific fixes:
{remediation_skill[:1000]}

CRITICAL RULES:
- Run each tool ONCE, analyze results, then move to next phase
- After ALL phases complete, call write_file to save the report to results/cert-in-report.json
- Then STOP — do not call any more tools
- If a tool fails or times out, note it and continue to next phase
- Only report VERIFIED vulnerabilities (not false positives)
- Include POC curl commands for each vulnerability
- Assign accurate CVSS 3.1 scores

REPORT JSON FORMAT (save to results/cert-in-report.json):
{{
  "target": "...",
  "executive_summary": "...",
  "vulnerability_summary": {{"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}},
  "vulnerabilities": [
    {{
      "title": "...",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cvss_vector": "CVSS:3.1/...",
      "cvss_score": 9.8,
      "cwe": "CWE-XX",
      "affected_component": "URL or service",
      "description": "...",
      "impact": "...",
      "poc": "curl command",
      "remediation": "specific fix with code"
    }}
  ]
}}
"""

    agent = Agent(
        name="Security Analyst",
        instructions=system_prompt,
        model=model,
        tools=SECURITY_TOOLS,
    )

    return agent


class SessionManager:
    """JSONL session transcripts — like Claude Code/Codex CLI."""

    def __init__(self, target: str, output_dir: str = "./results"):
        self.target = target
        self.session_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.session_dir = Path(output_dir) / "sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.session_file = self.session_dir / f"{self.session_id}-{target.replace('.', '-')}.jsonl"
        self.steps = []

    def log(self, event_type: str, data: dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            **data,
        }
        with open(self.session_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        self.steps.append(entry)

    def summary(self) -> dict:
        tool_calls = [s for s in self.steps if s["type"] == "tool_call"]
        return {
            "session_id": self.session_id,
            "target": self.target,
            "total_steps": len(self.steps),
            "tool_calls": len(tool_calls),
            "session_file": str(self.session_file),
        }


def run_merged_agent(target: str, model_config: dict, console=None) -> dict:
    """Run the merged agent — skills + tools in one unified mode."""

    agent = create_merged_agent(model_config)
    session = SessionManager(target, "./results")

    prompt = f"""Perform a full security assessment of {target}.

Follow the workflow phases in order:
1. Run run_httpx to probe the target
2. Run run_subfinder to find subdomains
3. Run run_nmap to scan ports
4. Run run_nuclei to scan for vulnerabilities
5. Verify findings with run_curl
6. Save report with write_file to results/cert-in-report.json

Then STOP. Do not call any more tools after writing the report.
"""

    # Header
    print(f"\n{BOLD}{MAGENTA}╭{'─'*55}╮{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {BOLD}Security Agent (Merged Mode){RESET}                          {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}├{'─'*55}┤{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Target:{RESET}  {target:<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Model:{RESET}   {model_config['name']:<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}API:{RESET}     {(model_config.get('api_base') or 'default'):<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Skills:{RESET}  9 skill files loaded{RESET}                          {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Session:{RESET} {session.session_id:<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}╰{'─'*55}╯{RESET}", flush=True)
    print(f"\n{DIM}  ● = tool call    ○ = result    ✗ = error{RESET}\n", flush=True)

    session.log("agent_start", {"target": target, "model": model_config["name"]})

    # Start heartbeat spinner in background thread
    import llm.tools as tools_mod
    heartbeat_stop = threading.Event()
    heartbeat_thread = threading.Thread(target=_heartbeat, args=(heartbeat_stop,), daemon=True)
    heartbeat_thread.start()

    try:
        result = Runner.run_sync(agent, prompt, max_turns=25)

        heartbeat_stop.set()
        heartbeat_thread.join(timeout=1)
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

        session.log("agent_end", {"status": "completed"})
        summary = session.summary()

        # Footer
        print(f"\n{BOLD}{GREEN}╭{'─'*55}╮{RESET}", flush=True)
        print(f"{BOLD}{GREEN}│{RESET} {BOLD}Agent Completed{RESET}                                       {BOLD}{GREEN}│{RESET}", flush=True)
        print(f"{BOLD}{GREEN}├{'─'*55}┤{RESET}", flush=True)
        print(f"{BOLD}{GREEN}│{RESET} {DIM}Session:{RESET} {summary['session_id']:<45} {BOLD}{GREEN}│{RESET}", flush=True)
        print(f"{BOLD}{GREEN}╰{'─'*55}╯{RESET}", flush=True)

        # Check for report
        report_path = Path("results") / "cert-in-report.json"
        if report_path.exists():
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            vuln_summary = report.get("vulnerability_summary", {})
            vulns = report.get("vulnerabilities", [])

            print(f"\n{BOLD}Vulnerability Summary:{RESET}", flush=True)
            print(f"  {RED}Critical:{RESET} {vuln_summary.get('critical', 0)}", flush=True)
            print(f"  {YELLOW}High:{RESET}     {vuln_summary.get('high', 0)}", flush=True)
            print(f"  {YELLOW}Medium:{RESET}   {vuln_summary.get('medium', 0)}", flush=True)
            print(f"  {GREEN}Low:{RESET}      {vuln_summary.get('low', 0)}", flush=True)
            print(f"  {BOLD}Total:{RESET}     {vuln_summary.get('total', len(vulns))}", flush=True)

            for i, v in enumerate(vulns, 1):
                sev = v.get("severity", "info").upper()
                color = RED if sev == "CRITICAL" else YELLOW if sev in ("HIGH", "MEDIUM") else GREEN
                print(f"\n  {color}{BOLD}[{i}]{RESET} {v.get('title', 'Untitled')} {DIM}({sev}, CVSS: {v.get('cvss_score', '?')}){RESET}", flush=True)

            print(f"\n{GREEN}Report:{RESET}  results/cert-in-report.json", flush=True)
            print(f"{GREEN}Session:{RESET} {summary['session_file']}", flush=True)
            return {"status": "success", "report": report, "session": summary}

        print(f"\n{YELLOW}No report file written.{RESET}", flush=True)
        print(f"{GREEN}Session:{RESET} {summary['session_file']}", flush=True)
        return {"status": "completed", "report": None, "session": summary}

    except KeyboardInterrupt:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=1)
        session.log("agent_interrupted", {"reason": "user_cancelled"})
        print(f"\n\n{YELLOW}{BOLD}Agent stopped by user (Ctrl+C){RESET}", flush=True)
        print(f"{GREEN}Session saved:{RESET} {session.session_file}", flush=True)
        return {"status": "interrupted", "session": session.summary()}

    except Exception as e:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=1)
        session.log("agent_error", {"error": str(e)})
        print(f"\n{RED}{BOLD}Error:{RESET} {e}", flush=True)
        print(f"{GREEN}Session:{RESET} {session.session_file}", flush=True)
        return {"status": "error", "error": str(e), "session": session.summary()}
