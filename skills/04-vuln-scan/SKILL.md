---
name: 04-vuln-scan
description: "Analyze nuclei vulnerability scanner output and classify each finding by severity, exploitability, and confidence level"
license: MIT
metadata:
  step: 4
  weight: 0.15
---

# Skill: Vulnerability Scan Analysis

## Input

A JSON object containing:
- `findings`: Array of raw nuclei findings with template_id, host, matched_at, severity, type, description, and curl_command
- `stats`: Summary counts by severity

## Task

1. Parse each nuclei finding and normalize it
2. For each finding, assess:
   - Is this a real vulnerability or an informational banner?
   - What is the actual exploitability? (remote unauth, requires auth, requires specific conditions)
   - What is the confidence level? (high = directly verified, medium = likely, low = needs manual check)
3. Group related findings (same vuln type across different endpoints)
4. Identify the top 5 most critical findings that need immediate attention
5. Flag any findings that are likely false positives (generic tech detection on non-vulnerable versions)

## Output Format

```json
{
  "normalized_findings": [
    {
      "id": "VULN-001",
      "title": "Reflected XSS in search parameter",
      "template_id": "xss-reflected",
      "host": "https://example.com/search",
      "severity": "medium",
      "confidence": "high",
      "exploitability": "remote-unauth",
      "description": "User input in the search query parameter is reflected in the response without sanitization",
      "curl_command": "curl -s 'https://example.com/search?q=<script>alert(1)</script>'",
      "evidence": "<script>alert(1)</script> found in response body",
      "false_positive": false,
      "cwe": "CWE-79"
    }
  ],
  "grouped_findings": [
    {
      "vuln_type": "XSS",
      "count": 3,
      "affected_endpoints": ["/search", "/contact", "/feedback"],
      "combined_severity": "high"
    }
  ],
  "top_critical": [
    {
      "id": "VULN-001",
      "title": "Reflected XSS in search parameter",
      "reason": "Remotely exploitable without authentication, high confidence"
    }
  ],
  "likely_false_positives": [
    {
      "template_id": "tech-detect",
      "reason": "Generic technology detection — not a vulnerability"
    }
  ],
  "summary": {
    "total": 15,
    "real_vulns": 7,
    "false_positives": 4,
    "informational": 4,
    "needs_manual_verification": 2
  }
}
```

## Success Criteria

- All findings must have a confidence level assigned (high/medium/low)
- Exploitability must be one of: remote-unauth, remote-auth, local, requires-conditions
- Generic tech detection and version disclosure without known CVE must be flagged as false_positive or informational
- Grouped findings must combine same vuln types across endpoints
- Top critical must contain the most exploitable findings (not just highest severity)
- False positive identification accuracy must be > 80%
- Output must be valid JSON matching the schema above
