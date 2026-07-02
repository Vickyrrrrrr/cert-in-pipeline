"""
CERT-In Vulnerability Pipeline — Main Entry Point

Usage:
  # List all supported providers
  python pipeline.py providers

  # Benchmark mode (test a model with sample data)
  python pipeline.py benchmark --provider ollama --model qwen2.5:7b
  python pipeline.py benchmark --provider glm --model glm-4-flash --api-key YOUR_KEY

  # Live mode (scan a real target)
  python pipeline.py live --target example.com --provider ollama --model qwen2.5:7b
  python pipeline.py live --target example.com --provider glm --model glm-4-flash --api-key YOUR_KEY

  # Score a previous run
  python pipeline.py score results/state.json
"""

import json
import os
import sys
import signal
from pathlib import Path

# Disable OpenAI Agents SDK tracing BEFORE any imports
os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "1"

# Handle Ctrl+C forcefully
def _force_exit(signum, frame):
    print("\n\nForce exit.", flush=True)
    os._exit(1)

signal.signal(signal.SIGINT, _force_exit)

# Fix Windows console encoding
if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")  # Set console to UTF-8
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pipeline.engine import PipelineEngine
from llm.interface import load_providers, list_providers, resolve_model_config
from scoring.evaluator import ScoringEvaluator

console = Console()


def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve_model(provider: str, model: str, api_key: str, api_base: str, config: dict) -> dict:
    """Resolve provider + model into a full model config."""

    if provider:
        resolved = resolve_model_config(provider, model, api_key)
        return {
            "name": resolved["name"],
            "api_base": resolved["api_base"],
            "api_key": resolved["api_key"],
            "temperature": config["model"].get("temperature", 0.1),
            "max_tokens": config["model"].get("max_tokens", 4096),
            "timeout": config["model"].get("timeout", 120),
        }

    if not model:
        model = config["model"]["name"]

    return {
        "name": model,
        "api_base": api_base or config["model"].get("api_base"),
        "api_key": api_key or config["model"].get("api_key"),
        "temperature": config["model"].get("temperature", 0.1),
        "max_tokens": config["model"].get("max_tokens", 4096),
        "timeout": config["model"].get("timeout", 120),
    }


@click.group()
def cli():
    """CERT-In Vulnerability Pipeline — supports 100+ LLM providers"""
    pass


@cli.command()
def providers():
    """List all supported LLM providers."""

    provider_list = list_providers()

    table = Table(title="\nSupported LLM Providers", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Type", style="dim")
    table.add_column("Base URL", style="dim")
    table.add_column("Models", style="green")

    for p in provider_list:
        models = ", ".join(p["models"][:3])
        if len(p["models"]) > 3:
            models += f" (+{len(p['models']) - 3} more)"
        table.add_row(
            p["id"],
            p["name"],
            p["type"],
            p["base_url"] or "(native SDK)",
            models,
        )

    console.print(table)
    console.print("\n[bold]Usage:[/]")
    console.print("  python pipeline.py benchmark --provider <id> --model <model> --api-key <key>")
    console.print("  python pipeline.py live --target example.com --provider <id> --model <model> --api-key <key>")
    console.print("\n[dim]Local providers (ollama, lmstudio, llamacpp) don't need an API key.[/]")


@cli.command()
@click.option("--provider", default=None, help="Provider ID from providers.yaml (e.g., ollama, glm, openai)")
@click.option("--model", default=None, help="Model name for the provider")
@click.option("--api-base", default=None, help="API base URL (overrides provider config)")
@click.option("--api-key", default=None, help="API key (overrides env var)")
@click.option("--config", default="config.yaml", help="Config file path")
@click.option("--output", default="./results", help="Output directory")
def benchmark(provider, model, api_base, api_key, config, output):
    """Run the pipeline in benchmark mode with test data."""

    cfg = load_config(config)
    cfg["model"] = resolve_model(provider, model, api_key, api_base, cfg)
    cfg["pipeline"]["mode"] = "benchmark"
    cfg["pipeline"]["output_dir"] = output

    console.print(Panel.fit(
        "[bold green]CERT-In Pipeline — Benchmark Mode[/]\n"
        f"Provider: {provider or 'custom'}\n"
        f"Model: {cfg['model']['name']}\n"
        f"API Base: {cfg['model']['api_base'] or '(default)'}\n"
        f"Mode: Benchmark (test data)\n"
        f"Output: {output}",
        border_style="green"
    ))

    engine = PipelineEngine(cfg, console)
    results = engine.run_benchmark()

    evaluator = ScoringEvaluator(cfg, console)
    score = evaluator.evaluate(results)
    evaluator.print_scoreboard(score)

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    with open(output_path / "benchmark-results.json", "w", encoding="utf-8") as f:
        json.dump({"results": results, "score": score}, f, indent=2)

    console.print(f"\n[green]Results saved to {output}/benchmark-results.json[/]")


@cli.command()
@click.option("--target", required=True, help="Target domain (e.g., example.com)")
@click.option("--provider", default=None, help="Provider ID from providers.yaml (e.g., ollama, glm, openai)")
@click.option("--model", default=None, help="Model name for the provider")
@click.option("--api-base", default=None, help="API base URL (overrides provider config)")
@click.option("--api-key", default=None, help="API key (overrides env var)")
@click.option("--config", default="config.yaml", help="Config file path")
@click.option("--output", default="./results", help="Output directory")
@click.option("--skip-tools", is_flag=True, help="Skip running security tools (use manual data)")
def live(target, provider, model, api_base, api_key, config, output, skip_tools):
    """Run the pipeline in live mode against a real target."""

    cfg = load_config(config)
    cfg["target"]["domain"] = target
    cfg["target"]["scope"] = [f"*.{target}"]
    cfg["model"] = resolve_model(provider, model, api_key, api_base, cfg)
    cfg["pipeline"]["mode"] = "live"
    cfg["pipeline"]["output_dir"] = output

    console.print(Panel.fit(
        f"[bold red]CERT-In Pipeline — Live Mode[/]\n"
        f"Target: {target}\n"
        f"Provider: {provider or 'custom'}\n"
        f"Model: {cfg['model']['name']}\n"
        f"API Base: {cfg['model']['api_base'] or '(default)'}\n"
        f"Skip tools: {skip_tools}",
        border_style="red"
    ))

    console.print("[yellow]WARNING: Only scan targets you have authorization to test.[/]")
    click.confirm("Do you have authorization to scan this target?", abort=True)

    engine = PipelineEngine(cfg, console)
    results = engine.run_live(target, skip_tools=skip_tools)

    evaluator = ScoringEvaluator(cfg, console)
    score = evaluator.evaluate(results)
    evaluator.print_scoreboard(score)

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    with open(output_path / "live-results.json", "w", encoding="utf-8") as f:
        json.dump({"results": results, "score": score}, f, indent=2, default=str)

    report_path = output_path / f"cert-in-report-{target.replace('.', '-')}.json"
    if "08-report" in results and results["08-report"].get("output"):
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(results["08-report"]["output"], f, indent=2)
        console.print(f"\n[green]CERT-In report saved to {report_path}[/]")
        console.print(f"[blue]Submit to: {cfg['cert_in']['email']}[/]")

    console.print(f"\n[green]Full results saved to {output}/live-results.json[/]")


@cli.command()
@click.option("--state", required=True, help="Path to state.json from a previous run")
@click.option("--config", default="config.yaml", help="Config file path")
def score(state, config):
    """Score a previous pipeline run."""

    cfg = load_config(config)
    with open(state, "r", encoding="utf-8") as f:
        results = json.load(f)

    evaluator = ScoringEvaluator(cfg, console)
    score = evaluator.evaluate(results)
    evaluator.print_scoreboard(score)


@cli.command()
@click.option("--target", required=True, help="Target domain (e.g., example.com)")
@click.option("--provider", default=None, help="Provider ID from providers.yaml")
@click.option("--model", default=None, help="Model name for the provider")
@click.option("--api-base", default=None, help="API base URL")
@click.option("--api-key", default=None, help="API key")
@click.option("--config", default="config.yaml", help="Config file path")
@click.option("--output", default="./results", help="Output directory")
def swarm(target, provider, model, api_base, api_key, config, output):
    """Run the multi-agent security swarm.

    5 specialized agents work in parallel:
      Coordinator -> Recon + Enum (parallel) -> Vuln -> Verify -> Report

    Each finding is independently verified to eliminate false positives.
    Raw tool output stored in SQLite evidence DB (context isolation).
    CVE/OWASP/CAPEC lookup via RAG tools.
    """

    cfg = load_config(config)
    model_cfg = resolve_model(provider, model, api_key, api_base, cfg)

    console.print(Panel.fit(
        f"[bold blue]CERT-In Pipeline -- Multi-Agent Swarm[/]\n"
        f"Target: {target}\n"
        f"Provider: {provider or 'custom'}\n"
        f"Model: {model_cfg['name']}\n"
        f"Agents: 5 (Recon, Enum, Vuln, Verify, Reporter)\n"
        f"Tools: 17 security + 4 RAG\n"
        f"Architecture: Parallel phases + Independent verification",
        border_style="blue"
    ))

    console.print("[yellow]WARNING: Only scan targets you have authorization to test.[/]")
    click.confirm("Do you have authorization to scan this target?", abort=True)

    Path(output).mkdir(parents=True, exist_ok=True)
    os.chdir(output)

    from llm.orchestrator import run_swarm_sync
    result = run_swarm_sync(target, model_cfg, console, provider or "")

    if result["status"] == "success":
        console.print(f"\n[bold green]Swarm complete![/] {result['findings']} verified findings.")
    else:
        console.print(f"\n[yellow]Swarm completed. {result.get('error', '')}[/]")


@cli.command()
@click.option("--target", required=True, help="Target domain (e.g., example.com)")
@click.option("--provider", default=None, help="Provider ID from providers.yaml")
@click.option("--model", default=None, help="Model name for the provider")
@click.option("--api-base", default=None, help="API base URL")
@click.option("--api-key", default=None, help="API key")
@click.option("--config", default="config.yaml", help="Config file path")
@click.option("--output", default="./results", help="Output directory")
def agent(target, provider, model, api_base, api_key, config, output):
    """Run the security agent -- merged mode (skills + tool execution).

    The LLM reads skill instructions, runs security tools, analyzes results,
    and generates a CERT-In report. Combines live mode (skills) and agent
    mode (tool execution) into one unified workflow.
    """

    cfg = load_config(config)
    model_cfg = resolve_model(provider, model, api_key, api_base, cfg)

    console.print(Panel.fit(
        f"[bold magenta]CERT-In Pipeline — Agent (Merged Mode)[/]\n"
        f"Target: {target}\n"
        f"Provider: {provider or 'custom'}\n"
        f"Model: {model_cfg['name']}\n"
        f"Skills: 9 loaded\n"
        f"Tools: 9 available",
        border_style="magenta"
    ))

    console.print("[yellow]WARNING: Only scan targets you have authorization to test.[/]")
    click.confirm("Do you have authorization to scan this target?", abort=True)

    Path(output).mkdir(parents=True, exist_ok=True)
    os.chdir(output)

    from llm.agent import run_merged_agent
    result = run_merged_agent(target, model_cfg, console)

    if result["status"] == "success":
        report = result.get("report", {})
        vulns = report.get("vulnerabilities", [])
        summary = report.get("vulnerability_summary", {})
        console.print(f"\n[bold green]Done![/] Found {summary.get('total', len(vulns))} vulnerabilities.")
    else:
        console.print(f"\n[yellow]Agent completed. {result.get('message', result.get('error', ''))}[/]")


if __name__ == "__main__":
    cli()
