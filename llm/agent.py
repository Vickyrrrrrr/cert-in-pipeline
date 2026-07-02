"""Security analyst agent — uses OpenAI Agents SDK with tool execution.

The LLM can call security tools (nuclei, nmap, subfinder, etc.) directly
and decide what to scan based on initial results.
"""

import json
import os
from pathlib import Path

from agents import Agent, Runner
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from llm.tools import SECURITY_TOOLS


def create_security_agent(model_config: dict) -> Agent:
    """Create a security analyst agent with tool execution capabilities."""

    model_name = model_config["name"]
    api_base = model_config.get("api_base")
    api_key = model_config.get("api_key") or "dummy"

    # Strip provider prefix for the OpenAI client (e.g., "openai/glm-5.2" -> "glm-5.2")
    if "/" in model_name:
        model_name = model_name.split("/", 1)[1]

    client = AsyncOpenAI(base_url=api_base, api_key=api_key)
    model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

    agent = Agent(
        name="Security Analyst",
        instructions="""You are an expert security analyst performing a vulnerability assessment.

You have access to the following tools:
- run_nuclei: Scan a target for known vulnerabilities
- run_nmap: Scan ports and services
- run_subfinder: Find subdomains
- run_httpx: Probe HTTP services and detect technologies
- run_ffuf: Fuzz directories and files
- run_curl: Send HTTP requests
- run_sqlmap: Test for SQL injection
- read_file: Read file contents
- write_file: Write to files
- run_command: Execute any shell command

WORKFLOW:
1. Start with recon: run httpx and subfinder on the target
2. Run nmap to find open ports and services
3. Run nuclei to find known vulnerabilities
4. For any web endpoints found, use ffuf to discover hidden paths
5. For any parameters found, use sqlmap to test for SQL injection
6. Use curl to verify findings manually
7. Write a final report to results/cert-in-report.json

RULES:
- Always verify findings before reporting them
- Do NOT report false positives
- Include proof of concept (curl commands) for each vulnerability
- Assign CVSS 3.1 scores to confirmed vulnerabilities
- Write the final report as valid JSON matching the CERT-In format
- If a tool fails or times out, note it and continue with other tools
- Be thorough — do not skip steps

OUTPUT:
After completing all scans, write your findings to results/cert-in-report.json
using the write_file tool. The report must be valid JSON with this structure:
{
  "target": "the target",
  "executive_summary": "2-3 paragraph summary",
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

Start by running httpx to probe the target, then subfinder to find subdomains,
then nmap for open ports, then nuclei for vulnerabilities.

Write your final report to results/cert-in-report-{target.replace('.', '-')}.json
"""

    if console:
        console.print(f"\n[bold cyan]Starting security agent for {target}...[/]")
        console.print(f"[dim]The LLM will autonomously run tools and analyze results.[/]")
        console.print(f"[dim]Model: {model_config['name']}[/]\n")

    try:
        result = Runner.run_sync(agent, prompt)

        if console:
            console.print(f"\n[green]Agent completed![/]")

        report_path = Path("results") / f"cert-in-report-{target.replace('.', '-')}.json"
        if report_path.exists():
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            return {"status": "success", "report": report, "agent_result": str(result)}
        else:
            return {
                "status": "completed",
                "report": None,
                "agent_output": str(result),
                "message": "Agent completed but no report file was written. Check agent output.",
            }

    except Exception as e:
        return {"status": "error", "error": str(e)}
