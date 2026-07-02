"""Security agent tools — callable by the LLM during analysis.

These tools let the LLM run real security scanners, read/write files,
and execute shell commands during the pipeline.
"""

import subprocess
import shutil
import json
import os
from pathlib import Path
from agents import function_tool, RunContextWrapper


def _check_tool(name: str) -> str | None:
    return shutil.which(name)


@function_tool
def run_nuclei(target: str, severity: str = "low,medium,high,critical") -> str:
    """Run nuclei vulnerability scanner against a target URL or domain.

    Args:
        target: The target URL or domain (e.g., https://example.com)
        severity: Severity filter (comma-separated: info,low,medium,high,critical)

    Returns:
        JSON string of nuclei findings
    """
    nuclei_path = _check_tool("nuclei")
    if not nuclei_path:
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
        return json.dumps({"findings": findings, "count": len(findings)})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nuclei timed out", "findings": []})
    except Exception as e:
        return json.dumps({"error": str(e), "findings": []})


@function_tool
def run_nmap(target: str, scan_type: str = "-sV --top-ports 1000") -> str:
    """Run nmap port scanner against a target.

    Args:
        target: The target domain or IP address
        scan_type: Nmap scan flags (e.g., "-sV --top-ports 1000" or "-sV -sC -p-")

    Returns:
        XML output from nmap
    """
    nmap_path = _check_tool("nmap")
    if not nmap_path:
        return json.dumps({"error": "nmap not installed", "hosts": []})

    cmd = [nmap_path] + scan_type.split() + ["-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        return result.stdout
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nmap timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@function_tool
def run_subfinder(domain: str) -> str:
    """Find subdomains for a domain using subfinder.

    Args:
        domain: The target domain (e.g., example.com)

    Returns:
        Newline-separated list of subdomains
    """
    subfinder_path = _check_tool("subfinder")
    if not subfinder_path:
        return json.dumps({"error": "subfinder not installed", "subdomains": []})

    cmd = [subfinder_path, "-d", domain, "-silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        subs = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
        return json.dumps({"subdomains": subs, "count": len(subs)})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "subfinder timed out", "subdomains": []})
    except Exception as e:
        return json.dumps({"error": str(e), "subdomains": []})


@function_tool
def run_httpx(urls: str) -> str:
    """Probe HTTP services using ProjectDiscovery httpx.

    Args:
        urls: Comma-separated URLs or domains to probe

    Returns:
        JSON string of HTTP response info
    """
    httpx_path = _check_tool("httpx")
    if not httpx_path:
        return json.dumps({"error": "httpx not installed", "results": []})

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
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "httpx timed out", "results": []})
    except Exception as e:
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_ffuf(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Fuzz directories and files using ffuf.

    Args:
        url: Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)
        wordlist: Path to wordlist file

    Returns:
        JSON string of discovered paths
    """
    ffuf_path = _check_tool("ffuf")
    if not ffuf_path:
        return json.dumps({"error": "ffuf not installed", "results": []})

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
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "ffuf timed out", "results": []})
    except Exception as e:
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_curl(url: str, method: str = "GET", headers: str = "") -> str:
    """Execute an HTTP request using curl.

    Args:
        url: The URL to request
        method: HTTP method (GET, POST, PUT, DELETE)
        headers: Optional headers (comma-separated, e.g., "Content-Type: application/json,Authorization: Bearer token")

    Returns:
        Response body and headers
    """
    curl_path = _check_tool("curl") or shutil.which("curl.exe")
    if not curl_path:
        return "curl not installed"

    cmd = [curl_path, "-s", "-i", "-X", method, "--max-time", "30", url]
    if headers:
        for h in headers.split(","):
            h = h.strip()
            if h:
                cmd.extend(["-H", h])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "curl timed out"
    except Exception as e:
        return f"Error: {e}"


@function_tool
def run_sqlmap(url: str, params: str = "") -> str:
    """Test for SQL injection using sqlmap.

    Args:
        url: Target URL (e.g., https://example.com/page?id=1)
        params: Additional sqlmap flags (e.g., "--forms --crawl=2")

    Returns:
        sqlmap output
    """
    sqlmap_path = _check_tool("sqlmap") or shutil.which("sqlmap")
    if not sqlmap_path:
        return json.dumps({"error": "sqlmap not installed"})

    cmd = [sqlmap_path, "-u", url, "--batch", "--output-dir", "/tmp/sqlmap-output"]
    if params:
        cmd.extend(params.split())
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "sqlmap timed out"
    except Exception as e:
        return f"Error: {e}"


@function_tool
def read_file(path: str) -> str:
    """Read the contents of a file.

    Args:
        path: Path to the file

    Returns:
        File contents as string
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file.

    Args:
        path: Path to the file
        content: Content to write

    Returns:
        Success or error message
    """
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully wrote to {path}"
    except Exception as e:
        return f"Error writing file: {e}"


@function_tool
def run_command(command: str) -> str:
    """Execute a shell command and return output.

    Args:
        command: The shell command to execute

    Returns:
        Command output (stdout + stderr)
    """
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120, check=False
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {e}"


# Export all tools (run_command excluded — LLM should use specialized tools)
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
