"""Security agent tools — each tool prints its execution live with colors.

Uses thread-safe printing with a lock shared with the heartbeat spinner.
All Unicode chars use Python escape sequences for cross-platform reliability.
"""

import subprocess
import shutil
import json
import os
import sys
import time
import threading
from pathlib import Path
from agents import function_tool

# Thread-safe printing lock (shared with heartbeat in agent.py)
_print_lock = threading.Lock()

# All subprocess calls use this to avoid UnicodeDecodeError on Windows
SUBPROCESS_KWARGS = {
    "capture_output": True,
    "text": True,
    "encoding": "utf-8",
    "errors": "replace",
    "check": False,
}

# ANSI colors
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RESET = "\033[0m"

# Unicode chars as escape sequences (cross-platform safe)
DOT = "\u25cf"       # bullet
CIRCLE = "\u25cb"    # circle
CROSS = "\u2717"     # cross mark
HOURGLASS = "\u23f3" # hourglass

# Global flag for heartbeat
_thinking = True


def _safe_print(msg):
    """Thread-safe print."""
    with _print_lock:
        print(msg, flush=True)


def _clear_line():
    """Clear current line."""
    with _print_lock:
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()


def _tool_call(name, **kwargs):
    """Print tool call: run_nuclei(target="...")"""
    global _thinking
    _thinking = False
    _clear_line()
    args = ", ".join(f'{k}="{v}"' if isinstance(v, str) else f'{k}={v}' for k, v in kwargs.items())
    if len(args) > 80:
        args = args[:77] + "..."
    _safe_print(f"  {CYAN}{DOT}{RESET} {BOLD}{name}({RESET}{DIM}{args}{RESET}{BOLD}){RESET}")


def _tool_result(msg, status="ok"):
    """Print result."""
    global _thinking
    _thinking = True
    if status == "ok":
        icon = f"{GREEN}{CIRCLE}{RESET}"
    elif status == "error":
        icon = f"{RED}{CROSS}{RESET}"
    else:
        icon = f"{YELLOW}{CIRCLE}{RESET}"
    _safe_print(f"  {icon} {msg}")


def _tool_running(msg):
    """Print running status."""
    _safe_print(f"  {DIM}{HOURGLASS} {msg}...{RESET}")


def _normalize_url(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        return "https://" + target
    return target


def _normalize_domain(target):
    domain = target.replace("https://", "").replace("http://", "")
    return domain.split("/")[0]


@function_tool
def run_nuclei(target, severity="low,medium,high,critical"):
    """Run nuclei vulnerability scanner against a target URL."""
    url = _normalize_url(target)
    _tool_call("run_nuclei", target=url, severity=severity)
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        _tool_result("nuclei not installed", "error")
        return json.dumps({"error": "not installed", "findings": []})
    _tool_running("scanning for vulnerabilities")
    cmd = [nuclei_path, "-u", url, "-json", "-silent", "-severity", severity, "-timeout", "10"]
    try:
        result = subprocess.run(cmd, timeout=300, **SUBPROCESS_KWARGS)
        findings = []
        for line in (result.stdout or "").strip().split("\n"):
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    f = json.loads(line)
                    findings.append({
                        "template_id": f.get("template-id", ""),
                        "name": f.get("info", {}).get("name", ""),
                        "severity": f.get("info", {}).get("severity", ""),
                        "host": f.get("host", ""),
                        "matched": f.get("matched-at", ""),
                        "description": f.get("info", {}).get("description", ""),
                        "curl": f.get("curl-command", ""),
                    })
                except json.JSONDecodeError:
                    continue
        if findings:
            by_sev = {}
            for f in findings:
                s = f.get("severity", "info")
                by_sev[s] = by_sev.get(s, 0) + 1
            sev_str = ", ".join(f"{v} {k}" for k, v in sorted(by_sev.items()))
            _tool_result(f"Found {len(findings)} vulnerabilities ({sev_str})")
        else:
            _tool_result("No vulnerabilities found")
        return json.dumps({"findings": findings, "count": len(findings)})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout", "findings": []})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e), "findings": []})


@function_tool
def run_nmap(target, scan_type="-sV --top-ports 100"):
    """Run nmap port scanner against a target."""
    domain = _normalize_domain(target)
    _tool_call("run_nmap", target=domain, scan_type=scan_type)
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        _tool_result("nmap not installed", "error")
        return json.dumps({"error": "not installed", "ports": []})
    _tool_running("scanning ports")
    cmd = [nmap_path] + scan_type.split() + ["-oX", "-", domain]
    try:
        result = subprocess.run(cmd, timeout=300, **SUBPROCESS_KWARGS)
        open_ports = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(result.stdout or "")
            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    service = port_elem.find("service")
                    open_ports.append({
                        "port": int(port_elem.get("portid", 0)),
                        "service": service.get("name", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                    })
        except Exception:
            pass
        if open_ports:
            port_str = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports[:10])
            _tool_result(f"Found {len(open_ports)} open ports: {port_str}")
        else:
            _tool_result("No open ports found (host may be behind firewall)")
        return json.dumps({"ports": open_ports, "raw_xml": (result.stdout or "")[:5000]})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout"})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e)})


@function_tool
def run_subfinder(domain):
    """Find subdomains for a domain."""
    domain = _normalize_domain(domain)
    _tool_call("run_subfinder", domain=domain)
    subfinder_path = shutil.which("subfinder")
    if not subfinder_path:
        _tool_result("subfinder not installed", "error")
        return json.dumps({"error": "not installed", "subdomains": []})
    _tool_running("enumerating subdomains")
    cmd = [subfinder_path, "-d", domain, "-silent"]
    try:
        result = subprocess.run(cmd, timeout=180, **SUBPROCESS_KWARGS)
        subs = [s.strip() for s in (result.stdout or "").strip().split("\n") if s.strip()]
        if subs:
            _tool_result(f"Found {len(subs)} subdomains")
        else:
            _tool_result("No subdomains found")
        return json.dumps({"subdomains": subs, "count": len(subs)})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout", "subdomains": []})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e), "subdomains": []})


@function_tool
def run_httpx(target):
    """Probe HTTP services and detect technologies."""
    url = _normalize_url(target)
    _tool_call("run_httpx", target=url)
    # Find ProjectDiscovery httpx (not Python httpx library)
    httpx_path = shutil.which("httpx")
    if httpx_path:
        try:
            check = subprocess.run([httpx_path, "-version"], capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace")
            if "projectdiscovery" not in (check.stdout + check.stderr).lower():
                httpx_path = None
        except Exception:
            httpx_path = None
    if not httpx_path:
        bin_httpx = os.path.join(os.path.expanduser("~"), "bin", "httpx.exe" if sys.platform == "win32" else "httpx")
        if os.path.exists(bin_httpx):
            httpx_path = bin_httpx
    if not httpx_path:
        _tool_result("httpx not installed", "error")
        return json.dumps({"error": "not installed", "results": []})
    _tool_running("probing HTTP service")
    cmd = [httpx_path, "-u", url, "-json", "-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects"]
    try:
        result = subprocess.run(cmd, timeout=60, **SUBPROCESS_KWARGS)
        results = []
        for line in (result.stdout or "").strip().split("\n"):
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if results:
            r = results[0]
            status = r.get("status_code", "?")
            title = r.get("title", "no title")
            tech = r.get("tech", [])
            tech_str = ", ".join(tech[:5]) if tech else "unknown"
            _tool_result(f"HTTP {status} - {title} - Tech: {tech_str}")
        else:
            _tool_result("No HTTP response")
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout", "results": []})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_ffuf(url, wordlist=""):
    """Fuzz directories. URL must contain FUZZ keyword."""
    _tool_call("run_ffuf", url=url)
    ffuf_path = shutil.which("ffuf")
    if not ffuf_path:
        _tool_result("ffuf not installed", "error")
        return json.dumps({"error": "not installed", "results": []})
    if not wordlist:
        wordlist_paths = ["/usr/share/wordlists/dirb/common.txt", os.path.join(os.environ.get("USERPROFILE", ""), "wordlists", "common.txt")]
        wordlist = next((p for p in wordlist_paths if os.path.exists(p)), "")
    if not wordlist:
        _tool_result("no wordlist found", "error")
        return json.dumps({"error": "no wordlist", "results": []})
    _tool_running("fuzzing directories")
    cmd = [ffuf_path, "-u", url, "-w", wordlist, "-json", "-mc", "200,301,302,403", "-t", "40", "-timeout", "10"]
    try:
        result = subprocess.run(cmd, timeout=300, **SUBPROCESS_KWARGS)
        results = []
        for line in (result.stdout or "").strip().split("\n"):
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    data = json.loads(line)
                    if "input" in data:
                        results.append({"path": data.get("input", {}).get("FUZZ", ""), "status": data.get("status", 0), "size": data.get("length", 0)})
                except json.JSONDecodeError:
                    continue
        if results:
            _tool_result(f"Found {len(results)} paths")
        else:
            _tool_result("No paths found")
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout", "results": []})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_curl(url, method="GET", headers=""):
    """Send an HTTP request to verify findings."""
    if not url.startswith("http"):
        url = _normalize_url(url)
    _tool_call("run_curl", method=method, url=url)
    curl_path = shutil.which("curl") or shutil.which("curl.exe")
    if not curl_path:
        _tool_result("curl not installed", "error")
        return "curl not installed"
    _tool_running("sending HTTP request")
    cmd = [curl_path, "-s", "-i", "-X", method, "--max-time", "30", "-L", "-k", url]
    if headers:
        for h in headers.split(","):
            h = h.strip()
            if h:
                cmd.extend(["-H", h])
    try:
        result = subprocess.run(cmd, timeout=60, **SUBPROCESS_KWARGS)
        stdout = result.stdout or ""
        status_line = ""
        for line in stdout.split("\n"):
            if line.startswith("HTTP/"):
                status_line = line.strip()
                break
        if status_line:
            _tool_result(f"{status_line} - {len(stdout)} bytes")
        else:
            _tool_result(f"Got {len(stdout)} bytes")
        return stdout
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return "timeout"
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return f"Error: {e}"


@function_tool
def run_sqlmap(url, params=""):
    """Test for SQL injection."""
    _tool_call("run_sqlmap", url=url)
    sqlmap_path = shutil.which("sqlmap")
    if not sqlmap_path:
        _tool_result("sqlmap not installed", "error")
        return json.dumps({"error": "not installed"})
    _tool_running("testing for SQL injection")
    cmd = [sqlmap_path, "-u", url, "--batch"]
    if params:
        cmd.extend(params.split())
    try:
        result = subprocess.run(cmd, timeout=300, **SUBPROCESS_KWARGS)
        output = (result.stdout or "") + (result.stderr or "")
        if "is vulnerable" in output.lower() or "sqlmap identified" in output.lower():
            _tool_result("SQL injection detected!")
        else:
            _tool_result("No SQL injection detected")
        return output
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return "timeout"
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return f"Error: {e}"


@function_tool
def read_file(path):
    """Read a file."""
    _tool_call("read_file", path=path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        _tool_result(f"Read {len(content)} chars")
        return content
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return f"Error: {e}"


@function_tool
def write_file(path, content):
    """Write content to a file."""
    _tool_call("write_file", path=path, size=f"{len(content)} chars")
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        _tool_result(f"Saved to {path}")
        return f"Successfully wrote to {path}"
    except Exception as e:
        _tool_result(f"error: {e}", "error")
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
