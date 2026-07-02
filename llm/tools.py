"""Security agent tools — fixed configurations for real data collection.

UX follows Claude Code pattern:
  ● tool_name(arg="value")     ← compact one-liner when calling
  ○ result summary              ← compact result when done
"""

import subprocess
import shutil
import json
import os
import time
from pathlib import Path
from agents import function_tool

# ANSI colors
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RESET = "\033[0m"


def _tool_call(name, **kwargs):
    """Print compact tool call like Claude Code: ● run_nuclei(target="...")"""
    args = ", ".join(f'{k}="{v}"' if isinstance(v, str) else f'{k}={v}' for k, v in kwargs.items())
    if len(args) > 80:
        args = args[:77] + "..."
    print(f"  {CYAN}●{RESET} {BOLD}{name}({RESET}{DIM}{args}{RESET}{BOLD}){RESET}", flush=True)


def _tool_result(msg, status="ok"):
    """Print compact result: ○ Found 5 vulnerabilities"""
    icon = GREEN + "○" + RESET if status == "ok" else RED + "✗" + RESET if status == "error" else YELLOW + "○" + RESET
    print(f"  {icon} {msg}", flush=True)


def _tool_running(msg):
    """Print running status."""
    print(f"  {DIM}⏳ {msg}...{RESET}", flush=True)


def _normalize_url(target):
    """Ensure URL has protocol."""
    if not target.startswith("http://") and not target.startswith("https://"):
        return "https://" + target
    return target


def _normalize_domain(target):
    """Extract domain from URL."""
    domain = target.replace("https://", "").replace("http://", "")
    return domain.split("/")[0]


@function_tool
def run_nuclei(target: str, severity: str = "low,medium,high,critical") -> str:
    """Run nuclei vulnerability scanner against a target URL."""
    url = _normalize_url(target)
    _tool_call("run_nuclei", target=url, severity=severity)

    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        _tool_result("nuclei not installed", "error")
        return json.dumps({"error": "nuclei not installed", "findings": []})

    _tool_running("scanning for vulnerabilities")
    cmd = [nuclei_path, "-u", url, "-json", "-silent", "-severity", severity, "-timeout", "10"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        findings = []
        for line in result.stdout.strip().split("\n"):
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
            sev_str = ", ".join(f"{v} {k}" for k, v in sorted(by_sev.items(), key=lambda x: ["critical","high","medium","low","info"].index(x[0]) if x[0] in ["critical","high","medium","low","info"] else 5))
            _tool_result(f"Found {len(findings)} vulnerabilities ({sev_str})")
        else:
            _tool_result("No vulnerabilities found")
        return json.dumps({"findings": findings, "count": len(findings)})
    except subprocess.TimeoutExpired:
        _tool_result("nuclei timed out (300s)", "error")
        return json.dumps({"error": "timeout", "findings": []})
    except Exception as e:
        _tool_result(f"nuclei error: {e}", "error")
        return json.dumps({"error": str(e), "findings": []})


@function_tool
def run_nmap(target: str, scan_type: str = "-sV --top-ports 100") -> str:
    """Run nmap port scanner against a target."""
    domain = _normalize_domain(target)
    _tool_call("run_nmap", target=domain, scan_type=scan_type)

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        _tool_result("nmap not installed", "error")
        return json.dumps({"error": "nmap not installed", "hosts": []})

    _tool_running("scanning ports")
    cmd = [nmap_path] + scan_type.split() + ["-oX", "-", domain]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)

        # Parse XML to extract open ports
        open_ports = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(result.stdout)
            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    service = port_elem.find("service")
                    open_ports.append({
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", ""),
                        "service": service.get("name", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                    })
        except ET.ParseError:
            pass

        if open_ports:
            port_str = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports[:10])
            if len(open_ports) > 10:
                port_str += f" (+{len(open_ports)-10} more)"
            _tool_result(f"Found {len(open_ports)} open ports: {port_str}")
        else:
            _tool_result("No open ports found (host may be behind firewall/CDN)")
        return json.dumps({"ports": open_ports, "raw_xml": result.stdout[:5000]})
    except subprocess.TimeoutExpired:
        _tool_result("nmap timed out (300s)", "error")
        return json.dumps({"error": "timeout"})
    except Exception as e:
        _tool_result(f"nmap error: {e}", "error")
        return json.dumps({"error": str(e)})


@function_tool
def run_subfinder(domain: str) -> str:
    """Find subdomains for a domain using subfinder."""
    domain = _normalize_domain(domain)
    _tool_call("run_subfinder", domain=domain)

    subfinder_path = shutil.which("subfinder")
    if not subfinder_path:
        _tool_result("subfinder not installed", "error")
        return json.dumps({"error": "not installed", "subdomains": []})

    _tool_running("enumerating subdomains")
    cmd = [subfinder_path, "-d", domain, "-silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        subs = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
        if subs:
            _tool_result(f"Found {len(subs)} subdomains")
        else:
            _tool_result("No subdomains found")
        return json.dumps({"subdomains": subs, "count": len(subs)})
    except subprocess.TimeoutExpired:
        _tool_result("subfinder timed out", "error")
        return json.dumps({"error": "timeout", "subdomains": []})
    except Exception as e:
        _tool_result(f"subfinder error: {e}", "error")
        return json.dumps({"error": str(e), "subdomains": []})


@function_tool
def run_httpx(target: str) -> str:
    """Probe HTTP services and detect technologies."""
    url = _normalize_url(target)
    _tool_call("run_httpx", target=url)

    httpx_path = shutil.which("httpx")
    if not httpx_path:
        _tool_result("httpx not installed", "error")
        return json.dumps({"error": "not installed", "results": []})

    _tool_running("probing HTTP service")
    cmd = [httpx_path, "-u", url, "-json", "-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        results = []
        for line in result.stdout.strip().split("\n"):
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
            _tool_result(f"HTTP {status} — {title} — Tech: {tech_str}")
        else:
            _tool_result("No HTTP response received")
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        _tool_result("httpx timed out", "error")
        return json.dumps({"error": "timeout", "results": []})
    except Exception as e:
        _tool_result(f"httpx error: {e}", "error")
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_ffuf(url: str, wordlist: str = "") -> str:
    """Fuzz directories and files. URL must contain FUZZ keyword (e.g. https://target/FUZZ)."""
    _tool_call("run_ffuf", url=url)

    ffuf_path = shutil.which("ffuf")
    if not ffuf_path:
        _tool_result("ffuf not installed", "error")
        return json.dumps({"error": "not installed", "results": []})

    # Try common wordlist paths
    if not wordlist:
        wordlist_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            os.path.join(os.environ.get("USERPROFILE", ""), "wordlists", "common.txt"),
        ]
        wordlist = next((p for p in wordlist_paths if os.path.exists(p)), "")
    
    if not wordlist:
        _tool_result("no wordlist found (install dirb or specify path)", "error")
        return json.dumps({"error": "no wordlist", "results": []})

    _tool_running("fuzzing directories")
    cmd = [ffuf_path, "-u", url, "-w", wordlist, "-json", "-mc", "200,301,302,403", "-t", "40", "-timeout", "10"]
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
            _tool_result(f"Found {len(results)} paths")
        else:
            _tool_result("No paths found")
        return json.dumps({"results": results, "count": len(results)})
    except subprocess.TimeoutExpired:
        _tool_result("ffuf timed out", "error")
        return json.dumps({"error": "timeout", "results": []})
    except Exception as e:
        _tool_result(f"ffuf error: {e}", "error")
        return json.dumps({"error": str(e), "results": []})


@function_tool
def run_curl(url: str, method: str = "GET", headers: str = "") -> str:
    """Send an HTTP request to verify findings."""
    url = _normalize_url(url) if not url.startswith("http") else url
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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        # Extract status line
        status_line = ""
        for line in result.stdout.split("\n"):
            if line.startswith("HTTP/"):
                status_line = line.strip()
                break
        body_size = len(result.stdout)
        if status_line:
            _tool_result(f"{status_line} — {body_size} bytes")
        else:
            _tool_result(f"Got {body_size} bytes")
        return result.stdout
    except subprocess.TimeoutExpired:
        _tool_result("curl timed out", "error")
        return "timeout"
    except Exception as e:
        _tool_result(f"curl error: {e}", "error")
        return f"Error: {e}"


@function_tool
def run_sqlmap(url: str, params: str = "") -> str:
    """Test for SQL injection using sqlmap."""
    _tool_call("run_sqlmap", url=url)

    sqlmap_path = shutil.which("sqlmap") or shutil.which("sqlmap")
    if not sqlmap_path:
        _tool_result("sqlmap not installed", "error")
        return json.dumps({"error": "not installed"})

    _tool_running("testing for SQL injection")
    cmd = [sqlmap_path, "-u", url, "--batch", "--output-dir", "/tmp/sqlmap-output"]
    if params:
        cmd.extend(params.split())
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        # Check if SQLi found
        if "is vulnerable" in result.stdout.lower() or "sqlmap identified" in result.stdout.lower():
            _tool_result("SQL injection detected!")
        else:
            _tool_result("No SQL injection detected")
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        _tool_result("sqlmap timed out", "error")
        return "timeout"
    except Exception as e:
        _tool_result(f"sqlmap error: {e}", "error")
        return f"Error: {e}"


@function_tool
def read_file(path: str) -> str:
    """Read the contents of a file."""
    _tool_call("read_file", path=path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        _tool_result(f"Read {len(content)} chars")
        return content
    except Exception as e:
        _tool_result(f"read error: {e}", "error")
        return f"Error: {e}"


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    _tool_call("write_file", path=path, size=f"{len(content)} chars")
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        _tool_result(f"Saved to {path}")
        return f"Successfully wrote to {path}"
    except Exception as e:
        _tool_result(f"write error: {e}", "error")
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
