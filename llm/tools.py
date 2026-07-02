"""Security agent tools — each tool prints its execution live with colors."""

import subprocess
import shutil
import json
import os
import sys
from pathlib import Path
from agents import function_tool

# ANSI colors
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"


def _log(msg):
    """Tool starting."""
    print(f"  {CYAN}>{RESET} {msg}", flush=True)


def _log_result(msg):
    """Tool succeeded."""
    print(f"  {GREEN}+{RESET} {msg}", flush=True)


def _log_error(msg):
    """Tool failed."""
    print(f"  {RED}!{RESET} {msg}", flush=True)


@function_tool
def run_nuclei(target: str, severity: str = "low,medium,high,critical") -> str:
    """Run nuclei vulnerability scanner against a target URL or domain."""
    _log(f"nuclei -u {target} -severity {severity}")
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        _log_error("nuclei not installed")
        return json.dumps({"error": "nuclei not installed", "findings": []})

    cmd = [nuclei_path, "-u", target, "-json", "-silent", "-severity", severity]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        findings = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if findings:
            _log_result(f"nuclei found {len(findings)} vulnerabilities")
        else:
            _log_result("nuclei found 0 vulnerabilities")
        return json.dumps({"findings": findings, "count": len(findings)})
    except subprocess.TimeoutExpired:
        _log_error("nuclei timed out")
        return json.dumps({"error": "timeout", "findings": []})
    except Exception as e:
        _log_error(f"nuclei error: {e}")
        return json.dumps({"error": str(e), "findings": []})


@function_tool
def run_nmap(target: str, scan_type: str = "-sV --top-ports 1000") -> str:
    """Run nmap port scanner against a target."""
    _log(f"nmap {scan_type} {target}")
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        _log_error("nmap not installed")
        return json.dumps({"error": "nmap not installed", "hosts": []})

    cmd = [nmap_path] + scan_type.split() + ["-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        _log_result(f"nmap completed ({len(result.stdout)} bytes of XML)")
        return result.stdout
    except subprocess.TimeoutExpired:
        _log_error("nmap timed out")
        return json.dumps({"error": "timeout"})
    except Exception as e:
        _log_error(f"nmap error: {e}")
        return json.dumps({"error": str(e)})


@function_tool
def run_subfinder(domain: str) -> str:
    """Find subdomains for a domain using subfinder."""
    _log(f"subfinder -d {domain}")
    subfinder_path = shutil.which("subfinder")
    if not subfinder_path:
        _log_error("subfinder not installed")
        return json.dumps({"error": "not installed", "subdomains": []})

    cmd = [subfinder_path, "-d", domain, "-silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        subs = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
        if subs:
            _log_result(f"subfinder found {len(subs)} subdomains")
        else:
            _log_result("subfinder found 0 subdomains")
        return json.dumps({"subdomains": subs, "count": len(subs)})
    except subprocess.TimeoutExpired:
        _log_error("subfinder timed out")
        return json.dumps({"error": "timeout", "subdomains": []})
    except Exception as e:
        _log_error(f"subfinder error: {e}")
        return json.dumps({"error": str(e), "subdomains": []})


@function_tool
def run_httpx(urls: str) -> str:
    """Probe HTTP services using ProjectDiscovery httpx."""
    _log(f"httpx -u {urls}")
    httpx_path = shutil.which("httpx")
    if not httpx_path:
        _log_error("httpx not installed")
        return json.dumps({"error": "not installed", "results": []})

    cmd = [httpx_path, "-u", urls, "-json", "-silent", "-status-code", "-title", "-tech-detect"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        results = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if results:
            _log_result(f"httpx probed {len(results)} hosts successfully")
        else:
            _log_result("httpx probed 0 hosts")
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        _log_error("httpx timed out")
        return json.dumps({"error": "timeout", "results": []})
    except Exception as e:
        _log_error(f"httpx error: {e}")
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_ffuf(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Fuzz directories and files using ffuf. URL must contain FUZZ keyword."""
    _log(f"ffuf -u {url}")
    ffuf_path = shutil.which("ffuf")
    if not ffuf_path:
        _log_error("ffuf not installed")
        return json.dumps({"error": "not installed", "results": []})

    cmd = [ffuf_path, "-u", url, "-w", wordlist, "-json", "-mc", "200,301,302,403", "-t", "40"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        results = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    data = json.loads(line)
                    if "input" in data:
                        results.append({
                            "path": data.get("input", {}).get("FUZZ", ""),
                            "status": data.get("status", 0),
                            "size": data.get("length", 0),
                        })
                except json.JSONDecodeError:
                    continue
        if results:
            _log_result(f"ffuf found {len(results)} paths")
        else:
            _log_result("ffuf found 0 paths")
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        _log_error("ffuf timed out")
        return json.dumps({"error": "timeout", "results": []})
    except Exception as e:
        _log_error(f"ffuf error: {e}")
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_curl(url: str, method: str = "GET", headers: str = "") -> str:
    """Execute an HTTP request using curl."""
    _log(f"curl -X {method} {url}")
    curl_path = shutil.which("curl") or shutil.which("curl.exe")
    if not curl_path:
        _log_error("curl not installed")
        return "curl not installed"

    cmd = [curl_path, "-s", "-i", "-X", method, "--max-time", "30", url]
    if headers:
        for h in headers.split(","):
            h = h.strip()
            if h:
                cmd.extend(["-H", h])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        _log_result(f"curl got {len(result.stdout)} bytes response")
        return result.stdout
    except subprocess.TimeoutExpired:
        _log_error("curl timed out")
        return "timeout"
    except Exception as e:
        _log_error(f"curl error: {e}")
        return f"Error: {e}"


@function_tool
def run_sqlmap(url: str, params: str = "") -> str:
    """Test for SQL injection using sqlmap."""
    _log(f"sqlmap -u {url}")
    sqlmap_path = shutil.which("sqlmap") or shutil.which("sqlmap")
    if not sqlmap_path:
        _log_error("sqlmap not installed")
        return json.dumps({"error": "not installed"})

    cmd = [sqlmap_path, "-u", url, "--batch"]
    if params:
        cmd.extend(params.split())
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        _log_result("sqlmap completed")
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        _log_error("sqlmap timed out")
        return "timeout"
    except Exception as e:
        _log_error(f"sqlmap error: {e}")
        return f"Error: {e}"


@function_tool
def read_file(path: str) -> str:
    """Read the contents of a file."""
    _log(f"read_file({path})")
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        _log_result(f"read {len(content)} chars from {path}")
        return content
    except Exception as e:
        _log_error(f"read error: {e}")
        return f"Error: {e}"


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    _log(f"write_file({path}) [{len(content)} chars]")
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        _log_result(f"report saved to {path}")
        return f"Successfully wrote to {path}"
    except Exception as e:
        _log_error(f"write error: {e}")
        return f"Error: {e}"


SECURITY_TOOLS = [
    run_nuclei,
    run_nmap,
    run_subfinder,
    run_httpx,
    run_ffuf,
    run_curl,
    run_sqlmap,
    read_file,
    write_file,
]
