---
name: 04-vuln-scan
description: "Classify nuclei findings, detect WAF bypass needs, identify API vulns, custom payload guidance, false positive pre-filtering"
license: MIT
metadata:
  step: 4
  weight: 0.15
---

# Skill: Vulnerability Scan Analysis

## Input
JSON with: findings (template_id, host, matched, severity, type, description, curl_command), stats

## Task
1. Parse each nuclei finding and normalize it
2. For each finding assess: real vulnerability vs informational banner?
3. Determine exploitability: remote-unauth, remote-auth, requires-conditions
4. Assign confidence: high (directly verified), medium (likely), low (needs manual check)
5. Group related findings (same vuln type across endpoints)
6. Identify top 5 most critical findings
7. Pre-filter obvious false positives (generic tech detection on non-vulnerable versions)
8. Check for API-specific vulnerabilities: broken auth, mass assignment, IDOR
9. Note WAF presence that may require bypass techniques
10. Identify findings that need manual verification with custom payloads

## Output Format
```json
{
  "normalized_findings": [
    {"id": "VULN-001", "title": "...", "template_id": "...", "host": "...", "severity": "...", "confidence": "high", "exploitability": "remote-unauth", "description": "...", "curl_command": "...", "evidence": "...", "false_positive": false, "cwe": "CWE-79"}
  ],
  "grouped_findings": [{"vuln_type": "XSS", "count": 3, "affected_endpoints": ["/search"], "combined_severity": "high"}],
  "top_critical": [{"id": "VULN-001", "title": "...", "reason": "..."}],
  "likely_false_positives": [{"template_id": "tech-detect", "reason": "Generic detection"}],
  "needs_manual_verification": [{"id": "VULN-005", "reason": "Needs custom payload"}],
  "summary": {"total": 0, "real_vulns": 0, "false_positives": 0, "informational": 0, "needs_manual_verification": 0}
}
```

## Success Criteria
- All findings must have confidence level (high/medium/low)
- Exploitability must be one of: remote-unauth, remote-auth, local, requires-conditions
- Generic tech detection without CVE = false_positive or informational
- Grouped findings must combine same vuln types
- Top critical must contain most exploitable findings
- False positive accuracy > 80%
- Output must be valid JSON
