"""Scoring evaluator — checks LLM output against success criteria."""

import json
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table


class ScoringEvaluator:
    def __init__(self, config: dict, console: Console):
        self.config = config
        self.console = console
        self.weights = config.get("scoring", {}).get("weights", {})
        self.pass_threshold = config.get("scoring", {}).get("pass_threshold", 0.80)

    def evaluate(self, results: dict) -> dict:
        scores = {}
        total_weighted = 0.0
        total_weight = 0.0

        for step_name, result in results.items():
            if not isinstance(result, dict):
                continue
            if result.get("status") != "success":
                scores[step_name] = {
                    "score": 0.0,
                    "weight": self.weights.get(step_name, 0),
                    "checks": [],
                    "error": result.get("error", "Step did not complete"),
                }
                total_weighted += 0.0
                total_weight += self.weights.get(step_name, 0)
                continue

            output = result.get("output")
            checks = self._run_checks(step_name, output)
            passed = sum(1 for c in checks if c["passed"])
            total = len(checks)
            score = passed / total if total > 0 else 0.0

            weight = self.weights.get(step_name, 0)
            scores[step_name] = {
                "score": score,
                "weight": weight,
                "weighted_score": score * weight,
                "checks": checks,
                "passed_checks": passed,
                "total_checks": total,
            }
            total_weighted += score * weight
            total_weight += weight

        final_score = total_weighted / total_weight if total_weight > 0 else 0.0
        passed = final_score >= self.pass_threshold

        return {
            "final_score": final_score,
            "pass_threshold": self.pass_threshold,
            "passed": passed,
            "step_scores": scores,
        }

    def _run_checks(self, step_name: str, output: dict) -> list[dict]:
        if output is None:
            return [{"name": "valid_json", "passed": False, "message": "Output is None"}]

        checks = []

        checks.append({
            "name": "valid_json",
            "passed": isinstance(output, dict),
            "message": "Output is valid JSON object" if isinstance(output, dict) else "Output is not a JSON object",
        })

        required_keys = self._get_required_keys(step_name)
        for key in required_keys:
            checks.append({
                "name": f"has_{key}",
                "passed": key in output,
                "message": f"Contains '{key}'" if key in output else f"Missing '{key}'",
            })

        if step_name == "04-vuln-scan":
            findings = output.get("normalized_findings", [])
            for f in findings:
                if "confidence" not in f:
                    checks.append({
                        "name": "confidence_assigned",
                        "passed": False,
                        "message": f"Finding '{f.get('title', '?')}' missing confidence",
                    })
                    break
            else:
                checks.append({
                    "name": "confidence_assigned",
                    "passed": True,
                    "message": "All findings have confidence levels",
                })

        if step_name == "06-severity":
            scored = output.get("scored_findings", [])
            for f in scored:
                vector = f.get("cvss_vector", "")
                if not vector.startswith("CVSS:3.1/"):
                    checks.append({
                        "name": "valid_cvss_vector",
                        "passed": False,
                        "message": f"Invalid CVSS vector: {vector}",
                    })
                    break
            else:
                checks.append({
                    "name": "valid_cvss_vector",
                    "passed": True,
                    "message": "All CVSS vectors are valid",
                })

        if step_name == "08-report":
            vulns = output.get("vulnerabilities", [])
            for v in vulns:
                if not v.get("poc"):
                    checks.append({
                        "name": "poc_present",
                        "passed": False,
                        "message": f"Vuln '{v.get('title', '?')}' missing POC",
                    })
                    break
            else:
                checks.append({
                    "name": "poc_present",
                    "passed": True,
                    "message": "All vulnerabilities have POC",
                })

        return checks

    def _get_required_keys(self, step_name: str) -> list[str]:
        return {
            "01-recon": ["technologies", "security_headers", "attack_surface_summary"],
            "02-enumeration": ["high_value_targets", "subdomain_ranking"],
            "03-port-scan": ["exposed_services", "attack_vectors"],
            "04-vuln-scan": ["normalized_findings", "summary"],
            "05-analysis": ["verified_findings", "false_positives", "stats"],
            "06-severity": ["scored_findings"],
            "07-exploitability": ["assessments"],
            "08-report": ["executive_summary", "vulnerabilities"],
            "09-remediation": ["remediation_plan", "summary"],
        }.get(step_name, [])

    def print_scoreboard(self, score: dict):
        table = Table(title="\nCERT-In Pipeline Scoreboard", show_lines=True)
        table.add_column("Step", style="cyan", no_wrap=True)
        table.add_column("Score", justify="center", style="white")
        table.add_column("Weight", justify="center")
        table.add_column("Checks", justify="center")
        table.add_column("Status", justify="center")

        for step, data in score.get("step_scores", {}).items():
            pct = f"{data['score']*100:.0f}%"
            weight = f"{data['weight']*100:.0f}%"
            passed = data.get("passed_checks", 0)
            total = data.get("total_checks", 0)
            status = "[green]PASS[/]" if data["score"] >= 0.7 else "[red]FAIL[/]"
            table.add_row(step, pct, weight, f"{passed}/{total}", status)

        self.console.print(table)

        final_pct = score["final_score"] * 100
        color = "green" if score["passed"] else "red"
        verdict = "CERT-IN PIPELINE READY" if score["passed"] else "NOT READY"

        self.console.print(
            f"\n[bold {color}]Final Score: {final_pct:.1f}%[/] "
            f"| Threshold: {score['pass_threshold']*100:.0f}%\n"
            f"[bold {color}]Verdict: {verdict}[/]\n"
        )
