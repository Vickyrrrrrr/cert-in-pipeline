"""Security analyst agent — Claude Code style UX with session management.

Features:
- Compact tool call display (● tool_name(args) / ○ result)
- JSONL session transcripts (save/resume)
- Proper error handling
- Summary at end
"""

import json
import os
import time
from pathlib import Path
from datetime import datetime

from agents import Agent, Runner, set_tracing_disabled
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from llm.tools import SECURITY_TOOLS

set_tracing_disabled(True)

# ANSI colors
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
RESET = "\033[0m"


class SessionManager:
    """Manages JSONL session transcripts — like Claude Code/Codex CLI."""

    def __init__(self, target: str, output_dir: str = "./results"):
        self.target = target
        self.session_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.session_dir = Path(output_dir) / "sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.session_file = self.session_dir / f"{self.session_id}-{target.replace('.', '-')}.jsonl"
        self.steps = []

    def log(self, event_type: str, data: dict):
        """Append an event to the JSONL session file."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            **data,
        }
        with open(self.session_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        self.steps.append(entry)

    def log_tool_call(self, tool_name: str, args: dict):
        self.log("tool_call", {"tool": tool_name, "args": args})

    def log_tool_result(self, tool_name: str, result: str, success: bool):
        self.log("tool_result", {"tool": tool_name, "result": result[:500], "success": success})

    def log_agent_message(self, message: str):
        self.log("agent_message", {"message": message[:500]})

    def summary(self) -> dict:
        tool_calls = [s for s in self.steps if s["type"] == "tool_call"]
        successes = [s for s in self.steps if s["type"] == "tool_result" and s.get("success")]
        failures = [s for s in self.steps if s["type"] == "tool_result" and not s.get("success")]
        return {
            "session_id": self.session_id,
            "target": self.target,
            "total_steps": len(self.steps),
            "tool_calls": len(tool_calls),
            "successful": len(successes),
            "failed": len(failures),
            "session_file": str(self.session_file),
        }


def create_security_agent(model_config: dict) -> Agent:
    """Create a security analyst agent."""

    model_name = model_config["name"]
    api_base = model_config.get("api_base")
    api_key = model_config.get("api_key") or "dummy"

    if "/" in model_name:
        model_name = model_name.split("/", 1)[1]

    client = AsyncOpenAI(base_url=api_base, api_key=api_key)
    model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

    agent = Agent(
        name="Security Analyst",
        instructions="""You are an expert security analyst. Use the tools provided to scan targets.

TOOLS (use these, not shell commands):
1. run_httpx(target) — Probe HTTP, detect tech stack
2. run_subfinder(domain) — Find subdomains
3. run_nmap(target) — Scan ports
4. run_nuclei(target) — Scan for vulnerabilities
5. run_curl(url) — Verify findings with HTTP request
6. run_ffuf(url) — Fuzz directories (url needs FUZZ keyword)
7. run_sqlmap(url) — Test SQL injection
8. write_file(path, content) — Save report

WORKFLOW:
1. run_httpx(target) — probe the target
2. run_subfinder(domain) — find subdomains
3. run_nmap(target) — scan ports
4. run_nuclei(target) — scan for vulns
5. run_curl(url) — verify findings
6. write_file("results/cert-in-report.json", report) — save report
7. STOP

RULES:
- Run each tool ONCE, then move to next
- After write_file, STOP — do not call more tools
- If tool fails, note it and continue
- Only report VERIFIED vulnerabilities
- Include POC (curl command) for each vuln
- Assign CVSS 3.1 scores

REPORT FORMAT (JSON):
{
  "target": "...",
  "executive_summary": "...",
  "vulnerability_summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
  "vulnerabilities": [
    {"title":"...","severity":"...","cvss_score":0,"cvss_vector":"CVSS:3.1/...","affected_component":"...","description":"...","impact":"...","poc":"curl ...","remediation":"..."}
  ]
}
""",
        model=model,
        tools=SECURITY_TOOLS,
    )

    return agent


def run_agent_scan(target: str, model_config: dict, console=None) -> dict:
    """Run the security agent with Claude Code-style UX."""

    agent = create_security_agent(model_config)
    session = SessionManager(target, "./results")

    prompt = f"""Perform a security assessment of {target}.

Call run_httpx first, then run_subfinder, run_nmap, run_nuclei, run_curl to verify, and finally write_file to save the report to results/cert-in-report.json.

Then STOP. Do not call any more tools after writing the report.
"""

    # Print header — Claude Code style
    print(f"\n{BOLD}{MAGENTA}╭{'─'*55}╮{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {BOLD}Security Agent{RESET}                                        {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}├{'─'*55}┤{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Target:{RESET}  {target:<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Model:{RESET}   {model_config['name']:<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}API:{RESET}     {(model_config.get('api_base') or 'default'):<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}│{RESET} {DIM}Session:{RESET} {session.session_id:<45} {BOLD}{MAGENTA}│{RESET}", flush=True)
    print(f"{BOLD}{MAGENTA}╰{'─'*55}╯{RESET}", flush=True)
    print(f"\n{DIM}  ● = tool call    ○ = result    ✗ = error{RESET}\n", flush=True)

    session.log("agent_start", {"target": target, "model": model_config["name"]})

    try:
        result = Runner.run_sync(agent, prompt, max_turns=30)

        session.log("agent_end", {"status": "completed"})

        # Print summary
        summary = session.summary()
        print(f"\n{BOLD}{GREEN}╭{'─'*55}╮{RESET}", flush=True)
        print(f"{BOLD}{GREEN}│{RESET} {BOLD}Agent Completed{RESET}                                       {BOLD}{GREEN}│{RESET}", flush=True)
        print(f"{BOLD}{GREEN}├{'─'*55}┤{RESET}", flush=True)
        print(f"{BOLD}{GREEN}│{RESET} {DIM}Tool calls:{RESET} {summary['tool_calls']:<41} {BOLD}{GREEN}│{RESET}", flush=True)
        print(f"{BOLD}{GREEN}│{RESET} {DIM}Successful:{RESET}  {summary['successful']:<41} {BOLD}{GREEN}│{RESET}", flush=True)
        print(f"{BOLD}{GREEN}│{RESET} {DIM}Failed:{RESET}      {summary['failed']:<41} {BOLD}{GREEN}│{RESET}", flush=True)
        print(f"{BOLD}{GREEN}│{RESET} {DIM}Session:{RESET}     {summary['session_id']:<41} {BOLD}{GREEN}│{RESET}", flush=True)
        print(f"{BOLD}{GREEN}╰{'─'*55}╯{RESET}", flush=True)

        # Check for report
        report_path = Path("results") / "cert-in-report.json"
        if report_path.exists():
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            # Print vulnerability summary
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

            print(f"\n{GREEN}Report saved:{RESET} results/cert-in-report.json", flush=True)
            print(f"{GREEN}Session saved:{RESET} {summary['session_file']}", flush=True)

            return {"status": "success", "report": report, "session": summary}

        print(f"\n{YELLOW}No report file written. Check agent output above.{RESET}", flush=True)
        print(f"{GREEN}Session saved:{RESET} {summary['session_file']}", flush=True)
        return {"status": "completed", "report": None, "session": summary}

    except Exception as e:
        session.log("agent_error", {"error": str(e)})
        print(f"\n{RED}{BOLD}Error:{RESET} {e}", flush=True)
        print(f"{GREEN}Session saved:{RESET} {session.session_file}", flush=True)
        return {"status": "error", "error": str(e), "session": session.summary()}
