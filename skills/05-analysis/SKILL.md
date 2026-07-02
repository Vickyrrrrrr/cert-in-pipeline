---
name: 05-analysis
description: "Verify vulnerability findings by analyzing evidence, distinguishing true positives from false positives, and confirming exploitability with proof of concept"
license: MIT
metadata:
  step: 5
  weight: 0.15
---

# Skill: False Positive Analysis & Verification

## Input

A JSON object containing:
- `findings`: Array of normalized vulnerability findings from step 04
- Each finding has: id, title, template_id, host, severity, confidence, curl_command, evidence

## Task

For each finding, determine if it is a TRUE POSITIVE or FALSE POSITIVE:

1. Analyze the evidence string — does it actually prove the vulnerability?
2. Check if the curl_command would actually demonstrate the vulnerability
3. Consider context: a version disclosure is not a vulnerability unless a known CVE exists for that version
4. Verify that the matched pattern is not a generic string (e.g., "nginx" in a response is not an XSS)
5. For each TRUE POSITIVE, write a working proof of concept
6. For each FALSE POSITIVE, explain why it is not exploitable

## Output Format

```json
{
  "verified_findings": [
    {
      "id": "VULN-001",
      "title": "Reflected XSS in search parameter",
      "confirmed": true,
      "confidence": 0.95,
      "reasoning": "The payload <script>alert(1)</script> is reflected unescaped in the HTML response body. The curl command confirms the response contains the payload verbatim. This is a classic reflected XSS.",
      "poc": "curl -s 'https://example.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E' | grep -o '<script>alert(document.cookie)</script>'",
      "poc_expected_result": "The grep should return the script tag, confirming the payload is reflected unescaped",
      "impact": "An attacker can execute arbitrary JavaScript in the victim's browser, stealing session cookies or performing actions on their behalf"
    }
  ],
  "false_positives": [
    {
      "id": "VULN-008",
      "title": "Nginx version disclosure",
      "confirmed": false,
      "confidence": 0.85,
      "reasoning": "The Server header reveals nginx 1.24.0. This is informational only — no known CVE affects this version. Version disclosure alone is not a vulnerability.",
      "impact": "Information disclosure — may help an attacker identify potential CVEs, but not directly exploitable"
    }
  ],
  "stats": {
    "total_analyzed": 15,
    "confirmed": 7,
    "false_positive": 5,
    "needs_manual_review": 3
  }
}
```

## Success Criteria

- Every finding must be classified as confirmed (true positive) or false_positive
- Confidence must be a float between 0 and 1
- Reasoning must reference the specific evidence (not generic statements)
- Every confirmed finding must have a working POC with expected result
- False positives must have a clear explanation of why they are not exploitable
- No true positive may be classified as false positive (recall must be 100%)
- False positive identification precision must be > 80%
- Output must be valid JSON matching the schema above
