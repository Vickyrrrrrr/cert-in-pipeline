"""Pipeline engine — orchestrates the full scan → LLM → score flow."""

import json
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from llm.interface import LLMInterface


class PipelineEngine:
    def __init__(self, config: dict, console: Console):
        self.config = config
        self.console = console
        self.llm = LLMInterface(config["model"])
        self.steps = config["pipeline"]["steps"]
        self.output_dir = Path(config["pipeline"]["output_dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _load_skill(self, step_name: str) -> dict:
        skill_dir = Path(__file__).parent.parent / "skills" / step_name
        skill_path = skill_dir / "SKILL.md"
        with open(skill_path, "r", encoding="utf-8") as f:
            return {"name": step_name, "content": f.read(), "dir": str(skill_dir)}

    def _load_test_data(self, step_name: str) -> dict | None:
        test_file = Path(__file__).parent.parent / "skills" / step_name / "test-data.json"
        if test_file.exists():
            with open(test_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def _run_llm_step(self, step_name: str, input_data: dict) -> dict:
        skill = self._load_skill(step_name)
        prompt = self._build_prompt(skill["content"], input_data)

        self.console.print(f"  [dim]Calling LLM for {step_name}...[/]")
        try:
            response = self.llm.complete(prompt)
            parsed = self._parse_json_response(response)
            return {
                "skill": step_name,
                "input": input_data,
                "output": parsed,
                "raw_response": response,
                "status": "success",
                "error": None,
            }
        except Exception as e:
            self.console.print(f"  [red]Error in {step_name}: {e}[/]")
            return {
                "skill": step_name,
                "input": input_data,
                "output": None,
                "raw_response": None,
                "status": "error",
                "error": str(e),
            }

    def _build_prompt(self, skill_content: str, input_data: dict) -> str:
        return (
            f"{skill_content}\n\n"
            f"---\n\n"
            f"## Input Data\n\n"
            f"```json\n{json.dumps(input_data, indent=2)}\n```\n\n"
            f"---\n\n"
            f"Analyze the input data according to the skill instructions above.\n"
            f"Return ONLY a valid JSON object matching the output format specified.\n"
            f"Do not include any text before or after the JSON.\n"
        )

    def _parse_json_response(self, response: str) -> dict:
        text = response.strip()

        # Try to extract JSON from code blocks
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.find("```", start)
            if end != -1:
                text = text[start:end].strip()
        elif "```" in text:
            start = text.index("```") + 3
            # Skip optional language tag on first line
            nl = text.find("\n", start)
            if nl != -1:
                start = nl + 1
            end = text.find("```", start)
            if end != -1:
                text = text[start:end].strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find first { and last } — extract JSON object
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            candidate = text[first_brace:last_brace + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # Try to find first [ and last ] — extract JSON array
        first_bracket = text.find("[")
        last_bracket = text.rfind("]")
        if first_bracket != -1 and last_bracket != -1 and last_bracket > first_bracket:
            candidate = text[first_bracket:last_bracket + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # Last resort: try progressively shorter substrings
        for i in range(len(text), 0, -1):
            try:
                return json.loads(text[:i])
            except json.JSONDecodeError:
                continue

        raise ValueError(f"Could not parse JSON from LLM response: {text[:200]}...")

    def run_benchmark(self) -> dict:
        results = {}
        self.console.print("\n[bold]Running benchmark pipeline...[/]\n")

        for i, step in enumerate(self.steps, 1):
            self.console.print(f"[bold cyan]Step {i}/{len(self.steps)}: {step}[/]")

            test_data = self._load_test_data(step)
            if test_data is None:
                self.console.print(f"  [yellow]No test data for {step}, using empty input[/]")
                test_data = {"target": self.config["target"]["domain"]}

            result = self._run_llm_step(step, test_data)
            results[step] = result

            if result["status"] == "success":
                self.console.print(f"  [green]OK[/]")
            else:
                self.console.print(f"  [red]FAILED: {result['error']}[/]")

        return results

    def run_live(self, target: str, skip_tools: bool = False) -> dict:
        results = {}

        if not skip_tools:
            from tools.scanner import Scanner
            from tools.port_scanner import PortScanner

            scanner = Scanner(self.config, self.console)
            port_scanner = PortScanner(self.config, self.console)

            self.console.print("\n[bold]Phase 1: Running security tools...[/]\n")

            recon_data = scanner.recon(target)
            results["01-recon"] = self._run_llm_step("01-recon", recon_data)

            enum_data = scanner.enumerate(target)
            results["02-enumeration"] = self._run_llm_step("02-enumeration", enum_data)

            port_data = port_scanner.scan(target, recon_data)
            results["03-port-scan"] = self._run_llm_step("03-port-scan", port_data)

            vuln_data = scanner.nuclei_scan(target)
            results["04-vuln-scan"] = self._run_llm_step("04-vuln-scan", vuln_data)
        else:
            self.console.print("\n[yellow]Skipping tools — using manual data input[/]")
            self.console.print("[yellow]Place your scan data in results/ directory[/]")

        self.console.print("\n[bold]Phase 2: LLM analysis pipeline...[/]\n")

        analysis_steps = ["05-analysis", "06-severity", "07-exploitability", "08-report", "09-remediation"]
        for step in analysis_steps:
            if step not in self.steps:
                continue

            self.console.print(f"[bold cyan]Step: {step}[/]")
            if step == "05-analysis" and "04-vuln-scan" in results:
                input_data = results["04-vuln-scan"].get("output", {})
            elif step == "06-severity" and "05-analysis" in results:
                input_data = results["05-analysis"].get("output", {})
            elif step == "07-exploitability" and "06-severity" in results:
                input_data = results["06-severity"].get("output", {})
            elif step == "08-report":
                input_data = {
                    k: v.get("output", {}) for k, v in results.items()
                    if v and v.get("output")
                }
            elif step == "09-remediation" and "08-report" in results:
                input_data = results["08-report"].get("output", {})
            else:
                input_data = {}

            result = self._run_llm_step(step, input_data)
            results[step] = result

            if result["status"] == "success":
                self.console.print(f"  [green]OK[/]")
            else:
                self.console.print(f"  [red]FAILED: {result['error']}[/]")

        state_path = self.output_dir / "state.json"
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)

        return results
