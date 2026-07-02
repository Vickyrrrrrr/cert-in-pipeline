---
name: 05-analysis
description: "Verify vulnerabilities: true/false positives, business logic flaws, IDOR, SSRF, race conditions, auth bypass, API abuse"
license: MIT
metadata:
  step: 5
  weight: 0.15
---

# Skill: False Positive Analysis & Verification

## Input
JSON with: findings (id, title, severity, confidence, curl_command, evidence)

## Task
For each finding, determine TRUE POSITIVE or FALSE POSITIVE:

1. Analyze evidence — does it actually prove the vulnerability?
2. Check if curl_command would demonstrate the vulnerability
3. Version disclosure without known CVE = not a vulnerability
4. Generic pattern match (e.g., "nginx" in response) = not XSS
5. For each TRUE POSITIVE, write a working proof of concept
6. For each FALSE POSITIVE, explain why it's not exploitable
7. Check for business logic flaws: price manipulation, workflow bypass, negative quantities
8. Check for IDOR: sequential IDs in URLs, missing authorization checks
9. Check for SSRF: URL parameters that fetch remote resources
10. Check for race conditions: double-submit, TOCTOU, balance manipulation
11. Check for authentication bypass: parameter pollution, JWT manipulation
12. Check for API abuse: missing rate limits, mass assignment, excessive data exposure

## Output Format
```json
{
  "verified_findings": [
    {"id": "VULN-001", "title": "...", "confirmed": true, "confidence": 0.95, "reasoning": "...", "poc": "curl ...", "poc_expected_result": "...", "impact": "..."}
  ],
  "false_positives": [
    {"id": "VULN-008", "title": "...", "confirmed": false, "confidence": 0.85, "reasoning": "...", "impact": "..."}
  ],
  "business_logic_issues": [
    {"title": "Price manipulation in cart", "description": "...", "poc": "...", "severity": "high"}
  ],
  "idor_findings": [
    {"url": "/api/users/1", "issue": "Can access other user's data by changing ID", "severity": "high"}
  ],
  "ssrf_findings": [
    {"url": "/fetch?url=http://169.254.169.254", "issue": "SSRF to cloud metadata", "severity": "critical"}
  ],
  "race_conditions": [
    {"url": "/withdraw", "issue": "Double withdrawal possible", "severity": "high"}
  ],
  "auth_bypass": [
    {"url": "/admin", "issue": "Admin accessible without auth", "severity": "critical"}
  ],
  "stats": {"total_analyzed": 0, "confirmed": 0, "false_positive": 0, "needs_manual_review": 0}
}
```

## Success Criteria
- Every finding classified as confirmed or false_positive
- Confidence must be float 0-1
- Every confirmed finding must have working POC with expected result
- False positives must have clear explanation
- Business logic, IDOR, SSRF, race conditions checked
- No true positive misclassified as false positive (100% recall)
- Output must be valid JSON
