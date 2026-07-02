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

# When True, tools suppress their own printing (swarm mode handles output)
_quiet = False


def set_quiet(value: bool = True):
    """Enable/disable quiet mode (swarm orchestrator uses this)."""
    global _quiet
    _quiet = value


def _safe_print(msg):
    """Thread-safe print."""
    with _print_lock:
        print(msg, flush=True)


def _clear_line():
    """Clear current line."""
    with _print_lock:
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()


def _tool_call(name, cmd=None, **kwargs):
    """Print tool call with actual command for reproducibility."""
    global _thinking
    _thinking = False
    if _quiet:
        return
    _clear_line()
    args = ", ".join(f'{k}="{v}"' if isinstance(v, str) else f'{k}={v}' for k, v in kwargs.items())
    if len(args) > 80:
        args = args[:77] + "..."
    _safe_print(f"  {CYAN}{DOT}{RESET} {BOLD}{name}({RESET}{DIM}{args}{RESET}{BOLD}){RESET}")
    # Show actual command for reproducibility
    if cmd:
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        if len(cmd_str) > 100:
            cmd_str = cmd_str[:97] + "..."
        _safe_print(f"  {DIM}  $ {cmd_str}{RESET}")


def _tool_result(msg, status="ok"):
    """Print result."""
    global _thinking
    _thinking = True
    if _quiet:
        return
    if status == "ok":
        icon = f"{GREEN}{CIRCLE}{RESET}"
    elif status == "error":
        icon = f"{RED}{CROSS}{RESET}"
    else:
        icon = f"{YELLOW}{CIRCLE}{RESET}"
    _safe_print(f"  {icon} {msg}")


def _tool_running(msg):
    """Print running status."""
    if _quiet:
        return
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
    _tool_call("run_nuclei", cmd=cmd, target=url, severity=severity)
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
    _tool_call("run_nmap", cmd=cmd, target=domain, scan_type=scan_type)
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
    _tool_call("run_subfinder", cmd=cmd, domain=domain)
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
    cmd = [httpx_path, "-u", url, "-json", "-silent", "-status-code", "-title", "-tech-detect",
           "-follow-redirects", "-timeout", "15",
           "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
    _tool_call("run_httpx", cmd=cmd, target=url)
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
    cmd = [curl_path, "-s", "-i", "-X", method, "--max-time", "30", "-L", "-k",
           "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
           url]
    if headers:
        for h in headers.split(","):
            h = h.strip()
            if h:
                cmd.extend(["-H", h])
    _tool_call("run_curl", cmd=cmd, method=method, url=url)
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


# ─── Evidence store tools (context isolation) ──────────────────────

@function_tool
def store_evidence(tool_name: str, target: str, command: str, raw_output: str):
    """Store raw tool output in the evidence database. Returns evidence_id (ev_XXXXXX).

    Use this when a tool produces large output. Store the raw output here
    and keep only the evidence_id + summary in your response.
    """
    _tool_call("store_evidence", tool=tool_name, target=target)
    try:
        from llm import evidence
        eid = evidence.store(tool_name, target, command, raw_output)
        _tool_result(f"Stored as {eid}")
        return json.dumps({"evidence_id": eid, "stored": True})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e), "stored": False})


@function_tool
def fetch_evidence(evidence_id: str):
    """Fetch raw evidence from the store by its ID (ev_XXXXXX).

    Use this to retrieve the full raw output of a previous tool call
    for verification or deeper analysis.
    """
    _tool_call("fetch_evidence", id=evidence_id)
    try:
        from llm import evidence
        result = evidence.fetch(evidence_id)
        if result:
            _tool_result(f"Fetched {result['tool']} output ({len(result['raw_output'])} chars)")
            return json.dumps(result)
        _tool_result("Not found", "error")
        return json.dumps({"error": "evidence not found"})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e)})


# ─── Expanded security tools ───────────────────────────────────────

@function_tool
def run_whatweb(target):
    """Fingerprint web technologies (CMS, frameworks, JS libraries, servers)."""
    url = _normalize_url(target)
    _tool_call("run_whatweb", target=url)
    whatweb_path = shutil.which("whatweb")
    if not whatweb_path:
        _tool_result("whatweb not installed", "error")
        return json.dumps({"error": "not installed", "tech": []})
    _tool_running("fingerprinting technologies")
    cmd = [whatweb_path, "-q", "--color=never", url]
    try:
        result = subprocess.run(cmd, timeout=60, **SUBPROCESS_KWARGS)
        output = result.stdout or ""
        _tool_result(f"Tech detected: {output.strip()[:100]}")
        return json.dumps({"tech": output.strip(), "raw": output[:2000]})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout"})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e)})


@function_tool
def run_nikto(target):
    """Run Nikto web server vulnerability scanner against a target."""
    url = _normalize_url(target)
    _tool_call("run_nikto", target=url)
    nikto_path = shutil.which("nikto")
    if not nikto_path:
        _tool_result("nikto not installed", "error")
        return json.dumps({"error": "not installed", "findings": []})
    _tool_running("scanning with Nikto")
    cmd = [nikto_path, "-h", url, "-Format", "json", "-nointeractive", "-timeout", "10"]
    try:
        result = subprocess.run(cmd, timeout=300, **SUBPROCESS_KWARGS)
        output = result.stdout or ""
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line and line.startswith("{"):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        _tool_result(f"Found {len(findings)} Nikto findings")
        return json.dumps({"findings": findings, "raw": output[:3000]})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout", "findings": []})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e), "findings": []})


@function_tool
def run_wpscan(target):
    """Scan WordPress installation for vulnerabilities, plugins, themes."""
    url = _normalize_url(target)
    _tool_call("run_wpscan", target=url)
    wpscan_path = shutil.which("wpscan")
    if not wpscan_path:
        _tool_result("wpscan not installed", "error")
        return json.dumps({"error": "not installed", "findings": []})
    _tool_running("scanning WordPress")
    cmd = [wpscan_path, "--url", url, "--format", "json", "--no-banner", "--random-user-agent"]
    try:
        result = subprocess.run(cmd, timeout=300, **SUBPROCESS_KWARGS)
        output = result.stdout or ""
        try:
            data = json.loads(output)
            _tool_result(f"WordPress scan complete: {len(data.get('interesting_findings', []))} findings")
            return json.dumps(data)
        except json.JSONDecodeError:
            _tool_result(f"Nikto output ({len(output)} chars)")
            return json.dumps({"raw": output[:3000]})
    except subprocess.TimeoutExpired:
        _tool_result("timed out", "error")
        return json.dumps({"error": "timeout"})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e)})


@function_tool
def run_searchsploit(query):
    """Search local ExploitDB database for exploits matching a query.

    Example: run_searchsploit("apache 2.4")
    """
    _tool_call("run_searchsploit", query=query)
    sp_path = shutil.which("searchsploit")
    if not sp_path:
        _tool_result("searchsploit not installed", "error")
        return json.dumps({"error": "not installed", "exploits": []})
    _tool_running("searching exploits")
    cmd = [sp_path, "-j", query]
    try:
        result = subprocess.run(cmd, timeout=30, **SUBPROCESS_KWARGS)
        output = result.stdout or ""
        try:
            data = json.loads(output)
            exploits = data.get("RESULTS_EXPLOIT", [])
            _tool_result(f"Found {len(exploits)} exploits")
            return json.dumps({"exploits": exploits[:10], "count": len(exploits)})
        except json.JSONDecodeError:
            _tool_result(f"Search done ({len(output)} chars)")
            return json.dumps({"raw": output[:2000]})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e)})


@function_tool
def run_dns_lookup(domain, record_type="A"):
    """DNS lookup for a domain. Types: A, AAAA, MX, TXT, NS, SOA, CNAME."""
    domain = _normalize_domain(domain)
    _tool_call("run_dns_lookup", domain=domain, type=record_type)
    _tool_running("resolving DNS")
    import socket
    try:
        if record_type == "A":
            results = socket.getaddrinfo(domain, None, socket.AF_INET)
            ips = list(set(r[4][0] for r in results))
            _tool_result(f"Resolved {len(ips)} A records")
            return json.dumps({"records": ips, "type": "A"})
        elif record_type == "MX":
            import subprocess as sp
            r = sp.run(["nslookup", "-type=mx", domain], capture_output=True, text=True, timeout=10)
            _tool_result("MX records retrieved")
            return json.dumps({"raw": r.stdout, "type": "MX"})
        else:
            import subprocess as sp
            r = sp.run(["nslookup", f"-type={record_type.lower()}", domain], capture_output=True, text=True, timeout=10)
            _tool_result(f"{record_type} records retrieved")
            return json.dumps({"raw": r.stdout, "type": record_type})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e)})


@function_tool
def check_security_headers(url):
    """Check HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)."""
    if not url.startswith("http"):
        url = _normalize_url(url)
    _tool_call("check_security_headers", url=url)
    _tool_running("checking security headers")
    curl_path = shutil.which("curl") or shutil.which("curl.exe")
    if not curl_path:
        _tool_result("curl not installed", "error")
        return json.dumps({"error": "curl not installed"})
    cmd = [curl_path, "-s", "-I", "--max-time", "15", "-k", "-A",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", url]
    try:
        result = subprocess.run(cmd, timeout=30, **SUBPROCESS_KWARGS)
        headers_raw = result.stdout or ""
        headers = {}
        for line in headers_raw.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        security_headers = {
            "content-security-policy": headers.get("content-security-policy", "MISSING"),
            "strict-transport-security": headers.get("strict-transport-security", "MISSING"),
            "x-frame-options": headers.get("x-frame-options", "MISSING"),
            "x-content-type-options": headers.get("x-content-type-options", "MISSING"),
            "referrer-policy": headers.get("referrer-policy", "MISSING"),
            "permissions-policy": headers.get("permissions-policy", "MISSING"),
        }
        missing = [k for k, v in security_headers.items() if v == "MISSING"]
        _tool_result(f"{len(missing)} security headers missing")
        return json.dumps({"headers": security_headers, "missing": missing, "all_headers": headers})
    except Exception as e:
        _tool_result(f"error: {e}", "error")
        return json.dumps({"error": str(e)})


# ─── Tool registries ───────────────────────────────────────────────

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

EXPANDED_TOOLS = [
    run_nuclei,
    run_nmap,
    run_subfinder,
    run_httpx,
    run_ffuf,
    run_curl,
    run_sqlmap,
    run_whatweb,
    run_nikto,
    run_wpscan,
    run_searchsploit,
    run_dns_lookup,
    check_security_headers,
    store_evidence,
    fetch_evidence,
    read_file,
    write_file,
]
