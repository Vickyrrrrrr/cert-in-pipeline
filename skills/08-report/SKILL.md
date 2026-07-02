---
name: 08-report
description: "Generate CERT-In compliant report with executive summary, detailed findings, POCs, compliance mapping, and coordinated disclosure timeline"
license: MIT
metadata:
  step: 8
  weight: 0.15
---

# Skill: CERT-In Report Generation

## Input
All previous step outputs: recon, enumeration, port_scan, vuln_scan, analysis, severity, exploitability

## Task
Generate a complete CERT-In vulnerability disclosure report:

1. Report header with reporter info, date, target organization
2. Executive summary (2-3 paragraphs) in plain English
3. Vulnerability summary table with counts by severity
4. For each confirmed vulnerability:
   - Title and CVE/CWE reference
   - CVSS vector and score
   - Affected component (URL, port, parameter)
   - Detailed description
   - Impact assessment
   - Reproduction steps (numbered, reproducible)
   - Proof of concept (working curl command)
   - Remediation (specific fix, not generic advice)
   - References (OWASP, CWE, vendor advisories)
5. Compliance mapping: CERT-In incident categories, IT Act sections
6. Coordinated disclosure timeline proposal
7. Format for email submission to CERT-In

## CERT-In Submission
- Email: vdisclose@cert-in.org.in
- PGP encryption recommended
- CERT-In is a CNA — can assign CVE IDs
- Policy: https://www.cert-in.org.in/RVDCP.jsp

## Output Format
```json
{
  "report_metadata": {"report_id": "RPT-...", "report_date": "...", "reporter": {"name": "...", "email": "..."}, "submission_email": "vdisclose@cert-in.org.in"},
  "target_info": {"organization": "...", "website": "...", "scope": ["*.example.com"]},
  "executive_summary": "...",
  "vulnerability_summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
  "vulnerabilities": [
    {
      "id": "VULN-2026-001",
      "title": "...",
      "cve": null,
      "cwe": "CWE-XX",
      "cwe_name": "...",
      "cvss_vector": "CVSS:3.1/...",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "affected_component": "...",
      "description": "...",
      "impact": "...",
      "reproduction_steps": ["1. ...", "2. ..."],
      "poc": "curl ...",
      "remediation": "Specific fix with code",
      "references": ["https://owasp.org/...", "https://cwe.mitre.org/..."]
    }
  ],
  "compliance_mapping": {
    "cert_in_categories": ["Unauthorized access to IT systems"],
    "it_act_sections": ["Section 43(b) — unauthorized access"],
    "reportable": true
  },
  "disclosure_timeline": {"proposed_timeline": [{"day": 0, "action": "..."}]}
}
```

## Success Criteria
- All confirmed vulnerabilities from step 05 included
- Each has: title, CVSS, description, impact, reproduction, POC, remediation
- Executive summary mentions most critical finding
- Remediation must be specific (actual config/code)
- POC must be copy-pasteable command
- References include at least one OWASP or CWE link per vuln
- Compliance mapping to CERT-In categories
- Output must be valid JSON
