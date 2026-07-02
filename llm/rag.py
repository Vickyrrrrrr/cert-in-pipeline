"""RAG Knowledge Base — CVE/OWASP/CAPEC lookup for the security agent.

Two-tier approach:
  1. LOCAL: Bundled OWASP WSTG + CAPEC + CWE knowledge (fast, offline)
  2. LIVE:  NVD API for real-time CVE lookup (network, always current)

The agent calls search_cve() or lookup_owasp() as function tools during
a scan — it fetches only the knowledge it needs, when it needs it,
rather than having everything dumped into its system prompt.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.parse
from pathlib import Path

from agents import function_tool


# ─── Local knowledge (bundled, offline) ─────────────────────────────

KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"

OWASP_TOP10 = {
    "A01": "Broken Access Control — IDOR, privilege escalation, missing auth checks",
    "A02": "Cryptographic Failures — weak ciphers, plaintext transit, hardcoded keys",
    "A03": "Injection — SQLi, NoSQLi, OS command, LDAP, XPath, template injection",
    "A04": "Insecure Design — missing rate limiting, business logic flaws, no threat modeling",
    "A05": "Security Misconfiguration — default creds, verbose errors, open S3 buckets",
    "A06": "Vulnerable Components — outdated libs with known CVEs",
    "A07": "Identification and Authentication Failures — weak passwords, session fixation",
    "A08": "Software and Data Integrity Failures — unsigned updates, deserialization",
    "A09": "Security Logging and Monitoring Failures — no audit trail, no alerting",
    "A10": "Server-Side Request Forgery (SSRF) — unvalidated URL fetching server-side",
}

CWE_COMMON = {
    "CWE-79": "Cross-site Scripting (XSS) — improper output encoding",
    "CWE-89": "SQL Injection — improper neutralization of SQL commands",
    "CWE-200": "Information Exposure — sensitive data visible to unauthorized actors",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-284": "Improper Access Control — improper authorization checks",
    "CWE-287": "Improper Authentication — incorrect auth implementation",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-408": "Incorrect Behavior Order — validate before sanitize",
    "CWE-538": "File and Directory Information Exposure — sensitive files in web root",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-614": "Sensitive Cookie Without Secure Flag",
    "CWE-693": "Protection Mechanism Failure — missing security headers",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames (clickjacking)",
    "CWE-1236": "Improper Neutralization of an Input Directive in CSV",
}


@function_tool
def search_cve(keyword: str, limit: int = 5) -> str:
    """Search NVD (National Vulnerability Database) for CVEs matching a keyword.

    Use this to find known vulnerabilities for a specific technology/version
    detected during scanning. Example: search_cve("apache 2.4.49")
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": min(limit, 20)})
    full_url = f"{url}?{params}"
    try:
        req = urllib.request.Request(full_url, headers={"User-Agent": "cert-in-pipeline"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        cves = []
        for vuln in data.get("vulnerabilities", [])[:limit]:
            cve_id = vuln.get("cve", {}).get("id", "")
            descriptions = vuln.get("cve", {}).get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
            metrics = vuln.get("cve", {}).get("metrics", {})
            cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            score = cvss.get("baseScore", "?")
            cves.append({"id": cve_id, "score": score, "description": desc[:200]})
        return json.dumps({"cves": cves, "count": len(cves)})
    except Exception as e:
        return json.dumps({"error": str(e), "cves": []})


@function_tool
def lookup_owasp(category: str) -> str:
    """Look up OWASP Top 10 category details by code (A01-A10) or keyword.

    Use this to map a finding to its OWASP category and get the
    description for the report. Example: lookup_owasp("A01") or lookup_owasp("injection")
    """
    category = category.upper().strip()
    if category in OWASP_TOP10:
        return json.dumps({"code": category, "description": OWASP_TOP10[category]})

    keyword = category.lower()
    for code, desc in OWASP_TOP10.items():
        if keyword in desc.lower():
            return json.dumps({"code": code, "description": desc})

    return json.dumps({"error": f"No OWASP category matching '{category}'", "all": OWASP_TOP10})


@function_tool
def lookup_cwe(cwe_id: str) -> str:
    """Look up CWE (Common Weakness Enumeration) details by ID.

    Use this to get the official CWE description for a finding.
    Example: lookup_cwe("CWE-79") or lookup_cwe("79")
    """
    cwe_id = cwe_id.upper().strip()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"

    if cwe_id in CWE_COMMON:
        return json.dumps({"id": cwe_id, "description": CWE_COMMON[cwe_id]})

    return json.dumps({"id": cwe_id, "description": "Unknown CWE — check https://cwe.mitre.org for details"})


@function_tool
def lookup_exploit(query: str) -> str:
    """Search ExploitDB for public exploits matching a keyword.

    Use this to find known exploits for a detected service/version.
    Example: lookup_exploit("apache struts 2")
    """
    url = f"https://exploit-db.com/search?q={urllib.parse.quote(query)}"
    try:
        api_url = "https://www.exploit-db.com/api/search"
        params = urllib.parse.urlencode({"q": query, "limit": 5})
        req = urllib.request.Request(
            f"{api_url}?{params}",
            headers={"User-Agent": "cert-in-pipeline", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        exploits = []
        for item in data.get("data", data.get("results", []))[:5]:
            exploits.append({
                "id": item.get("id", item.get("edbid", "")),
                "title": item.get("title", ""),
                "type": item.get("type", ""),
                "platform": item.get("platform", ""),
            })
        return json.dumps({"exploits": exploits, "count": len(exploits), "url": url})
    except Exception:
        return json.dumps({"error": "ExploitDB API unavailable", "search_url": url, "exploits": []})


RAG_TOOLS = [search_cve, lookup_owasp, lookup_cwe, lookup_exploit]
