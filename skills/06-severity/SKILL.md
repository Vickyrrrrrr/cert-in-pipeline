---
name: 06-severity
description: "Assign accurate CVSS 3.1 scores and severity ratings to confirmed vulnerabilities based on their exploitability and impact"
license: MIT
metadata:
  step: 6
  weight: 0.10
---

# Skill: CVSS Severity Scoring

## Input

A JSON object containing:
- `findings`: Array of confirmed vulnerabilities from step 05
- Each finding has: id, title, confirmed, confidence, poc, impact

## Task

For each confirmed vulnerability, assign a CVSS 3.1 score:

1. Determine the Attack Vector (Network/Adjacent/Local/Physical)
2. Determine the Attack Complexity (Low/High)
3. Determine Privileges Required (None/Low/High)
4. Determine User Interaction (None/Required)
5. Determine Scope (Unchanged/Changed)
6. Determine Impact on Confidentiality (None/Low/High)
7. Determine Impact on Integrity (None/Low/High)
8. Determine Impact on Availability (None/Low/High)
9. Calculate the CVSS score and severity rating
10. Assign the appropriate CWE ID

## Output Format

```json
{
  "scored_findings": [
    {
      "id": "VULN-001",
      "title": "Reflected XSS in search parameter",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
      "cvss_score": 6.1,
      "severity": "MEDIUM",
      "cvss_breakdown": {
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "Required",
        "scope": "Unchanged",
        "confidentiality": "Low",
        "integrity": "Low",
        "availability": "None"
      },
      "cwe_id": "CWE-79",
      "cwe_name": "Improper Neutralization of Input During Web Page Generation",
      "scoring_rationale": "Network-based attack with low complexity. No privileges required but user must click a crafted link. Limited impact on confidentiality and integrity, no availability impact."
    }
  ]
}
```

## CVSS Reference

| Severity | Score Range |
|----------|-------------|
| None | 0.0 |
| Low | 0.1 - 3.9 |
| Medium | 4.0 - 6.9 |
| High | 7.0 - 8.9 |
| Critical | 9.0 - 10.0 |

## Success Criteria

- CVSS vector must be syntactically valid (parseable by cvss library)
- CVSS score must match the vector (not arbitrary)
- Severity rating must match the score range
- CWE ID must be relevant to the vulnerability type
- Scoring rationale must justify each metric choice
- Reflected XSS should typically score 6.1 (Medium)
- SQL injection with data exfiltration should typically score 9.8 (Critical)
- RCE should typically score 9.8 (Critical)
- Information disclosure should typically score 3.1-5.3 (Low-Medium)
- Output must be valid JSON matching the schema above
