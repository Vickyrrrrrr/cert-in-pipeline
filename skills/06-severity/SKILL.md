---
name: 06-severity
description: "CVSS 3.1 scoring with environmental context, temporal factors, and risk adjustment"
license: MIT
metadata:
  step: 6
  weight: 0.10
---

# Skill: CVSS Severity Scoring

## Input
JSON with: findings (id, title, confirmed, confidence, poc, impact)

## Task
For each confirmed vulnerability:
1. Determine Attack Vector (Network/Adjacent/Local/Physical)
2. Determine Attack Complexity (Low/High)
3. Determine Privileges Required (None/Low/High)
4. Determine User Interaction (None/Required)
5. Determine Scope (Unchanged/Changed)
6. Determine Impact: Confidentiality, Integrity, Availability (None/Low/High)
7. Calculate CVSS score and severity
8. Apply environmental factors: internet-facing, sensitive data, critical infrastructure
9. Assign CWE ID
10. Note temporal factors: exploit available, patch available, confidence in report

## CVSS Reference
| Severity | Score |
|----------|-------|
| None | 0.0 |
| Low | 0.1-3.9 |
| Medium | 4.0-6.9 |
| High | 7.0-8.9 |
| Critical | 9.0-10.0 |

## Common Scores
- Reflected XSS: 6.1 (Medium)
- Stored XSS: 8.7 (High)
- SQL Injection (data exfil): 9.8 (Critical)
- RCE: 9.8 (Critical)
- SSRF: 9.1 (Critical)
- IDOR: 7.5 (High)
- Info disclosure: 3.1-5.3 (Low-Medium)
- Path traversal: 7.5 (High)
- Open redirect: 6.1 (Medium)

## Output Format
```json
{
  "scored_findings": [
    {
      "id": "VULN-001",
      "title": "...",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
      "cvss_score": 6.1,
      "severity": "MEDIUM",
      "cvss_breakdown": {"attack_vector": "Network", "attack_complexity": "Low", "privileges_required": "None", "user_interaction": "Required", "scope": "Unchanged", "confidentiality": "Low", "integrity": "Low", "availability": "None"},
      "cwe_id": "CWE-79",
      "cwe_name": "Improper Neutralization of Input During Web Page Generation",
      "environmental_factors": {"internet_facing": true, "sensitive_data": true, "adjustment": "+0.5 if critical infrastructure"},
      "scoring_rationale": "Justification for each metric"
    }
  ]
}
```

## Success Criteria
- CVSS vector must be syntactically valid
- CVSS score must match the vector
- Severity rating must match the score range
- CWE ID must be relevant
- Environmental factors considered
- RCE/SQLi should typically score 9.8
- Output must be valid JSON
