"""Security analyst agent — uses OpenAI Agents SDK with live output via hooks."""

import json
import os
from pathlib import Path

from agents import (
    Agent, Runner, set_tracing_disabled,
    RunHooks, AgentHooks,
)
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from llm.tools import SECURITY_TOOLS

set_tracing_disabled(True)


class LiveHooks(RunHooks):
    """Hooks that print agent actions in real-time — like OpenCode/Claude Code."""

    def on_agent_start(self, context, agent):
        print(f"\n[AGENT] {agent.name} started", flush=True)

    def on_tool_start(self, context, agent, tool):
        name = getattr(tool, 'name', str(tool))
        print(f"\n  > CALLING: {name}", flush=True)

    def on_tool_end(self, context, agent, tool, result):
        name = getattr(tool, 'name', str(tool))
        # Truncate result for display
        s = str(result)
        if len(s) > 150:
            s = s[:150] + "..."
        print(f"  < RESULT ({name}): {s}", flush=True)

    def on_agent_end(self, context, agent, output):
        print(f"\n[AGENT] {agent.name} finished", flush=True)


def create_security_agent(model_config: dict) -> Agent:
    """Create a security analyst agent with tool execution capabilities."""

    model_name = model_config["name"]
    api_base = model_config.get("api_base")
    api_key = model_config.get("api_key") or "dummy"

    if "/" in model_name:
        model_name = model_name.split("/", 1)[1]

    client = AsyncOpenAI(base_url=api_base, api_key=api_key)
    model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

    agent = Agent(
        name="Security Analyst",
        instructions="""You are an expert security analyst performing a vulnerability assessment.

You have access to specialized security tools:

1. run_httpx(target) — Probe HTTP services, detect technologies
2. run_subfinder(domain) — Find subdomains
3. run_nmap(target) — Scan ports and services
4. run_nuclei(target) — Scan for known vulnerabilities
5. run_ffuf(url) — Fuzz directories (url must contain FUZZ keyword)
6. run_curl(url) — Send HTTP requests to verify findings
7. run_sqlmap(url) — Test for SQL injection
8. write_file(path, content) — Save your report

WORKFLOW:
Step 1: Call run_httpx with the target URL (e.g. https://testphp.vulnweb.com)
Step 2: Call run_subfinder with the domain
Step 3: Call run_nmap with the target
Step 4: Call run_nuclei with the target URL
Step 5: Call run_curl to verify any findings
Step 6: Call write_file to save report to results/cert-in-report.json
Step 7: STOP. Do not call more tools.

RULES:
- Run each tool ONCE then move on
- After writing the report, STOP
- If a tool errors, continue to next step
- Include POC curl commands in the report
- Assign CVSS scores to vulnerabilities

REPORT JSON FORMAT (write to results/cert-in-report.json):
{
  "target": "...",
  "executive_summary": "...",
  "vulnerability_summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
  "vulnerabilities": [
    {"title": "...", "severity": "...", "cvss_score": 0, "poc": "...", "remediation": "..."}
  ]
}
""",
        model=model,
        tools=SECURITY_TOOLS,
    )

    return agent


def run_agent_scan(target: str, model_config: dict, console=None) -> dict:
    """Run the security agent against a target with live output."""

    agent = create_security_agent(model_config)
    hooks = LiveHooks()

    prompt = f"""Perform a security assessment of {target}.

Call run_httpx first, then run_subfinder, run_nmap, run_nuclei, run_curl to verify, and finally write_file to save the report to results/cert-in-report.json.

Then STOP. Do not call any more tools after writing the report.
"""

    if console:
        console.print(f"\n[bold cyan]Agent starting...[/]")
        console.print(f"[dim]Target: {target}[/]")
        console.print(f"[dim]Model: {model_config['name']}[/]")
        console.print(f"[dim]Live output: ON (via hooks)[/]\n")

    try:
        result = Runner.run_sync(agent, prompt, max_turns=30, hooks=hooks)

        if console:
            console.print(f"\n[bold green]Agent finished![/]")
            console.print(f"[dim]Final output: {str(result.final_output)[:300]}[/]")

        report_path = Path("results") / "cert-in-report.json"
        if report_path.exists():
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            return {"status": "success", "report": report}

        return {
            "status": "completed",
            "report": None,
            "output": str(result.final_output)[:500],
        }

    except Exception as e:
        if console:
            console.print(f"\n[red]Error: {e}[/]")
        return {"status": "error", "error": str(e)}
