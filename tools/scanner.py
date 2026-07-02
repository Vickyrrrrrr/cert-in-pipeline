"""Security tool wrappers — subfinder, httpx, nuclei, nmap, ffuf."""

import json
import subprocess
import shutil
from pathlib import Path

from rich.console import Console


class Scanner:
    def __init__(self, config: dict, console: Console):
        self.config = config
        self.console = console
        self.tool_config = config.get("tools", {})

    def _check_tool(self, name: str) -> bool:
        return shutil.which(name) is not None

    def _run(self, cmd: list[str], timeout: int = 300) -> str:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            self.console.print(f"  [yellow]Timeout running {' '.join(cmd[:3])}[/]")
            return ""
        except FileNotFoundError:
            self.console.print(f"  [yellow]Tool not found: {cmd[0]}[/]")
            return ""

    def recon(self, target: str) -> dict:
        self.console.print(f"  [dim]Running recon on {target}...[/]")

        data = {"target": target, "technologies": [], "dns": {}, "ssl": {}, "headers": {}, "whois": {}}

        import httpx as httpx_lib
        try:
            resp = httpx_lib.get(f"https://{target}", timeout=10, verify=False, follow_redirects=True)
            data["headers"] = dict(resp.headers)
            data["ssl"] = {"status": "valid"} if resp.url.scheme == "https" else {"status": "none"}
        except Exception as e:
            data["headers"] = {"error": str(e)}

        if self._check_tool("subfinder"):
            output = self._run(["subfinder", "-d", target, "-silent", "-json"],
                               timeout=self.tool_config.get("subfinder", {}).get("timeout", 300))
            data["subfinder_raw"] = output

        return data

    def enumerate(self, target: str) -> dict:
        self.console.print(f"  [dim]Enumerating subdomains for {target}...[/]")

        data = {"target": target, "subdomains": [], "directories": [], "summary": {}}

        if self._check_tool("subfinder"):
            output = self._run(
                ["subfinder", "-d", target, "-silent"],
                timeout=self.tool_config.get("subfinder", {}).get("timeout", 300),
            )
            subs = [s.strip() for s in output.strip().split("\n") if s.strip()]
            for sub in subs:
                data["subdomains"].append({"host": sub, "ip": "", "status": 0, "title": ""})

        data["summary"] = {
            "total_subdomains": len(data["subdomains"]),
            "live": 0,
            "interesting": 0,
        }
        return data

    def nuclei_scan(self, target: str) -> dict:
        self.console.print(f"  [dim]Running nuclei scan on {target}...[/]")

        data = {"target": target, "findings": [], "stats": {}}

        if not self._check_tool("nuclei"):
            self.console.print("  [yellow]nuclei not installed — skipping[/]")
            return data

        output = self._run(
            ["nuclei", "-u", target, "-json", "-silent"],
            timeout=self.tool_config.get("nuclei", {}).get("timeout", 600),
        )

        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                f = json.loads(line)
                findings.append({
                    "template_id": f.get("template-id", ""),
                    "template": f.get("template-path", ""),
                    "host": f.get("host", ""),
                    "matched": f.get("matched-at", ""),
                    "type": f.get("type", ""),
                    "severity": f.get("severity", "info"),
                    "description": f.get("description", ""),
                    "curl_command": f.get("curl-command", ""),
                })
            except json.JSONDecodeError:
                continue

        data["findings"] = findings
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
        data["stats"] = {"total": len(findings), **severity_counts}

        return data
