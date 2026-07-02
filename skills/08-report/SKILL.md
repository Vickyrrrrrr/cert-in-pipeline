---
name: 08-report
description: "Generate a CERT-In compliant vulnerability disclosure report from all pipeline findings, formatted for submission to vdisclose@cert-in.org.in"
license: MIT
metadata:
  step: 8
  weight: 0.15
---

# Skill: CERT-In Report Generation

## Input

A JSON object containing all previous step outputs:
- `recon`: Technology stack and attack surface (step 01)
- `enumeration`: High-value targets and sensitive paths (step 02)
- `port_scan`: Exposed services and dangerous exposures (step 03)
- `vuln_scan`: Normalized vulnerability findings (step 04)
- `analysis`: Verified true/false positives (step 05)
- `severity`: CVSS scored findings (step 06)
- `exploitability`: Attack scenarios and risk assessment (step 07)

## Task

Generate a complete CERT-In vulnerability disclosure report:

1. Create a report header with reporter info, date, and target organization
2. Write an executive summary (2-3 paragraphs) in plain English
3. Create a vulnerability summary table with counts by severity
4. For each confirmed vulnerability, write a detailed entry including:
   - Title and CVE/CWE reference
   - CVSS vector and score
   - Affected component (URL, port, parameter)
   - Detailed description (what the vulnerability is)
   - Impact (what an attacker can do)
   - Reproduction steps (numbered, reproducible)
   - Proof of concept (working curl command or HTTP request)
   - Remediation (specific fix, not generic advice)
   - References (OWASP, CWE, vendor advisories)
5. Include a coordinated disclosure timeline proposal
6. Format the report for email submission to CERT-In

## Output Format

Return a JSON object with the report:

```json
{
  "report_metadata": {
    "report_id": "RPT-2026-001",
    "report_date": "2026-07-02",
    "reporter": {
      "name": "[RESEARCHER NAME]",
      "email": "[RESEARCHER EMAIL]",
      "organization": "[ORGANIZATION]"
    },
    "submission_email": "vdisclose@cert-in.org.in",
    "pgp_required": true
  },
  "target_info": {
    "organization": "Example Corp",
    "website": "https://example.com",
    "scope": ["*.example.com"],
    "discovery_method": "Automated pipeline + manual verification"
  },
  "executive_summary": "A security assessment of example.com identified 3 confirmed vulnerabilities, including 1 reflected XSS and 1 exposed git repository. The most critical finding is the exposed .git directory which leaks the application source code and potentially database credentials. Immediate remediation is recommended.",
  "vulnerability_summary": {
    "total": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0
  },
  "vulnerabilities": [
    {
      "id": "VULN-2026-001",
      "title": "Exposed Git Repository Leaks Source Code",
      "cve": null,
      "cwe": "CWE-538",
      "cwe_name": "File and Directory Information Exposure",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      "cvss_score": 9.1,
      "severity": "CRITICAL",
      "affected_component": "https://example.com/.git/config",
      "description": "The .git directory is accessible via the web server. This exposes the entire Git repository including source code, commit history, and potentially hardcoded credentials or API keys in configuration files.",
      "impact": "An attacker can download the entire source code of the application, analyze it for vulnerabilities, and find hardcoded credentials. This can lead to full application compromise.",
      "reproduction_steps": [
        "Navigate to https://example.com/.git/config in a web browser",
        "If the file contents are displayed, the git repository is exposed",
        "Use git-dumper tool to download the full repository: git-dumper https://example.com/.git/ ./output"
      ],
      "poc": "curl -s https://example.com/.git/config",
      "poc_expected_result": "Returns the git config file contents including [core] repository format version",
      "remediation": "Add a rule to the web server configuration to block access to .git directories. For nginx: location ~ /\.git { deny all; }. For Apache: RedirectMatch 404 /\\.git.",
      "references": [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cwe.mitre.org/data/definitions/538.html"
      ]
    }
  ],
  "disclosure_timeline": {
    "proposed_timeline": [
      {"day": 0, "action": "Report submitted to CERT-In"},
      {"day": 7, "action": "CERT-In validates and notifies vendor"},
      {"day": 30, "action": "Vendor patches or provides mitigation"},
      {"day": 90, "action": "Public disclosure if vendor is unresponsive"}
    ]
  }
}
```

## CERT-In Submission Notes

- Email: vdisclose@cert-in.org.in
- PGP encryption is recommended for sensitive reports
- CERT-In acts as a CVE Numbering Authority (CNA) and can assign CVE IDs
- Reports are processed per the RVDCP policy at https://www.cert-in.org.in/RVDCP.jsp

## Success Criteria

- Report must include all confirmed vulnerabilities from step 05
- Each vulnerability must have: title, CVSS, description, impact, reproduction steps, POC, remediation
- Executive summary must mention the most critical finding
- Remediation must be specific (actual config/code, not "update your software")
- POC must be a copy-pasteable command (curl, wget, or browser URL)
- References must include at least one OWASP or CWE link per vulnerability
- Report must be valid JSON matching the schema above
- Disclosure timeline must follow responsible disclosure principles
