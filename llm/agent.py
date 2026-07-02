"""Security analyst agent — uses OpenAI Agents SDK with tool execution.

The LLM can call security tools (nuclei, nmap, subfinder, etc.) directly
and decide what to scan based on initial results.
"""

import json
import os
from pathlib import Path

from agents import Agent, Runner, set_tracing_disabled, set_default_openai_client
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from llm.tools import SECURITY_TOOLS

# Disable tracing — we're not using OpenAI's backend
set_tracing_disabled(True)


def create_security_agent(model_config: dict) -> Agent:
    """Create a security analyst agent with tool execution capabilities."""

    model_name = model_config["name"]
    api_base = model_config.get("api_base")
    api_key = model_config.get("api_key") or "dummy"

    # Strip provider prefix (e.g., "openai/glm-5.2" -> "glm-5.2")
    if "/" in model_name:
        model_name = model_name.split("/", 1)[1]

    # Create custom OpenAI-compatible client pointing to GLM/Ollama/etc.
    client = AsyncOpenAI(base_url=api_base, api_key=api_key)

    # Set as default client but don't use it for tracing (avoids 401 errors)
    set_default_openai_client(client, use_for_tracing=False)

    model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

    agent = Agent(
        name="Security Analyst",
        instructions="""You are an expert security analyst performing a vulnerability assessment.

You have access to specialized security tools. Use THESE tools, not generic commands:

1. run_httpx(target) — Probe HTTP services, detect technologies
2. run_subfinder(domain) — Find subdomains
3. run_nmap(target) — Scan ports and services
4. run_nuclei(target) — Scan for known vulnerabilities
5. run_ffuf(url) — Fuzz directories and files
6. run_curl(url) — Send HTTP requests to verify findings
7. run_sqlmap(url) — Test for SQL injection
8. write_file(path, content) — Save your report

WORKFLOW (follow this exact order):
Step 1: Call run_httpx with the target URL
Step 2: Call run_subfinder with the target domain
Step 3: Call run_nmap with the target
Step 4: Call run_nuclei with the target URL
Step 5: If nuclei finds web endpoints, call run_ffuf with the URL + /FUZZ
Step 6: If you find parameters, call run_sqlmap
Step 7: Use run_curl to verify any findings
Step 8: Call write_file to save your report as JSON

CRITICAL RULES:
- Use ONLY the tools listed above. Do NOT try to run shell commands.
- Run each tool ONCE, collect the result, then move to the next step.
- After all tools have run, write the report using write_file and STOP.
- Do NOT call tools after writing the report.
- If a tool returns an error, note it and continue to the next step.

REPORT FORMAT (write to results/cert-in-report.json):
{
  "target": "the target",
  "executive_summary": "summary of findings",
  "vulnerability_summary": {"total": N, "critical": N, "high": N, "medium": N, "low": N},
  "vulnerabilities": [
    {
      "title": "...",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cvss_vector": "CVSS:3.1/...",
      "cvss_score": 9.8,
      "affected_component": "URL or service",
      "description": "...",
      "impact": "...",
      "poc": "curl command",
      "remediation": "specific fix"
    }
  ]
}
""",
        model=model,
        tools=SECURITY_TOOLS,
    )

    return agent


def run_agent_scan(target: str, model_config: dict, console=None) -> dict:
    """Run the security agent against a target.

    The agent will autonomously:
    1. Run recon tools
    2. Scan for vulnerabilities
    3. Verify findings
    4. Generate a CERT-In report
    """

    agent = create_security_agent(model_config)

    prompt = f"""Perform a full security assessment of: {target}

Steps:
1. Call run_httpx to probe the target
2. Call run_subfinder to find subdomains
3. Call run_nmap to scan ports
4. Call run_nuclei to scan for vulnerabilities
5. If you find web endpoints, call run_ffuf to find hidden paths
6. Use run_curl to verify any findings
7. Call write_file to save your report as JSON to results/cert-in-report.json

After running all tools, write the final report and STOP.
Do not call any more tools after writing the report.
"""

    if console:
        console.print(f"\n[bold cyan]Starting security agent for {target}...[/]")
        console.print(f"[dim]Model: {model_config['name']}[/]")
        console.print(f"[dim]API: {model_config.get('api_base', 'default')}[/]")
        console.print(f"[dim]Tracing: disabled[/]\n")

    try:
        result = Runner.run_sync(agent, prompt, max_turns=30)

        if console:
            console.print(f"\n[green]Agent completed![/]")
            console.print(f"[dim]Steps taken: {len(result.new_items)}[/]")

        # Check for report file
        report_paths = [
            Path("results") / "cert-in-report.json",
            Path("results") / f"cert-in-report-{target.replace('.', '-')}.json",
        ]

        for report_path in report_paths:
            if report_path.exists():
                with open(report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
                return {"status": "success", "report": report, "agent_result": result.final_output}

        return {
            "status": "completed",
            "report": None,
            "agent_output": result.final_output,
            "message": "Agent completed. Check output above for findings.",
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}
