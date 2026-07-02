"""Security analyst agent — uses OpenAI Agents SDK with tool execution.

Shows real-time agent actions (tool calls, results) to the user.
"""

import json
import os
import asyncio
from pathlib import Path

from agents import Agent, Runner, set_tracing_disabled
from agents.items import TResponseInputItem, RunItem, MessageOutputItem, ToolCallItem, ToolCallOutputItem
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from llm.tools import SECURITY_TOOLS

set_tracing_disabled(True)


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

You have access to specialized security tools. Use THESE tools, not generic commands:

1. run_httpx(target) — Probe HTTP services, detect technologies
2. run_subfinder(domain) — Find subdomains
3. run_nmap(target) — Scan ports and services
4. run_nuclei(target) — Scan for known vulnerabilities
5. run_ffuf(url) — Fuzz directories and files (url must contain FUZZ keyword)
6. run_curl(url) — Send HTTP requests to verify findings
7. run_sqlmap(url) — Test for SQL injection
8. write_file(path, content) — Save your report

WORKFLOW (follow this exact order):
Step 1: Call run_httpx with the target URL (e.g., https://target)
Step 2: Call run_subfinder with the target domain
Step 3: Call run_nmap with the target
Step 4: Call run_nuclei with the target URL
Step 5: If nuclei finds web endpoints, call run_ffuf with URL + /FUZZ
Step 6: If you find parameters, call run_sqlmap
Step 7: Use run_curl to verify any findings
Step 8: Call write_file to save your report as JSON to results/cert-in-report.json

CRITICAL RULES:
- Use ONLY the tools listed above.
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


async def _run_streamed(agent: Agent, prompt: str, console) -> str:
    """Run agent with streaming — shows real-time tool calls and results."""

    from agents import ItemHelpers

    result = Runner.run_streamed(agent, prompt, max_turns=30)

    step = 0
    async for event in result.stream_events:

        if event.type == "agent_updated_stream_event":
            name = event.agent.name if event.agent else "Agent"
            console.print(f"\n[bold cyan]Agent: {name}[/]")

        elif event.type == "run_item_stream_event":
            item = event.item

            if isinstance(item, MessageOutputItem):
                text = ItemHelpers.text_message_output(item)
                if text and len(text) > 10:
                    step += 1
                    short = text[:200] + "..." if len(text) > 200 else text
                    console.print(f"\n[yellow]Step {step}: Agent thinking[/]")
                    console.print(f"[dim]{short}[/]")

            elif isinstance(item, ToolCallItem):
                step += 1
                raw = item.raw_item
                tool_name = "?"
                tool_args = ""

                if hasattr(raw, 'name'):
                    tool_name = raw.name
                elif hasattr(raw, 'function') and hasattr(raw.function, 'name'):
                    tool_name = raw.function.name
                    tool_args = raw.function.arguments or ""

                # Try to parse arguments
                if tool_args and isinstance(tool_args, str):
                    try:
                        args = json.loads(tool_args)
                        args_str = ", ".join(f"{k}={v}" for k, v in args.items())
                    except json.JSONDecodeError:
                        args_str = tool_args[:100]
                elif tool_args and isinstance(tool_args, dict):
                    args_str = ", ".join(f"{k}={v}" for k, v in tool_args.items())
                else:
                    args_str = ""

                console.print(f"\n[bold green]Step {step}: Calling {tool_name}({args_str})[/]")

            elif isinstance(item, ToolCallOutputItem):
                output = item.output
                if isinstance(output, str):
                    # Truncate long outputs
                    if len(output) > 300:
                        short = output[:300] + "..."
                    else:
                        short = output
                    console.print(f"[dim]Result: {short}[/]")
                else:
                    short = str(output)[:300]
                    console.print(f"[dim]Result: {short}[/]")

    return result.final_output


def run_agent_scan(target: str, model_config: dict, console=None) -> dict:
    """Run the security agent against a target with live output."""

    agent = create_security_agent(model_config)

    prompt = f"""Perform a full security assessment of: {target}

Call run_httpx first to probe the target, then run_subfinder, run_nmap, run_nuclei, etc.
After all tools have run, use write_file to save the report to results/cert-in-report.json
Then STOP. Do not call any more tools.
"""

    if console:
        console.print(f"\n[bold cyan]Starting security agent for {target}...[/]")
        console.print(f"[dim]Model: {model_config['name']}[/]")
        console.print(f"[dim]API: {model_config.get('api_base', 'default')}[/]")
        console.print(f"[dim]Max turns: 30[/]")
        console.print(f"[dim]Live output: ON[/]\n")

    try:
        # Run the async streaming function
        final_output = asyncio.run(_run_streamed(agent, prompt, console))

        if console:
            console.print(f"\n[bold green]Agent completed![/]")

        # Check for report file
        report_path = Path("results") / "cert-in-report.json"
        if report_path.exists():
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            return {"status": "success", "report": report, "agent_output": final_output}

        return {
            "status": "completed",
            "report": None,
            "agent_output": final_output,
            "message": "Agent completed. Check output above.",
        }

    except Exception as e:
        if console:
            console.print(f"\n[red]Error: {e}[/]")
        return {"status": "error", "error": str(e)}
