---
name: 09-remediation
description: "Specific remediation with code examples, verification steps, rollback plans, and priority matrix"
license: MIT
metadata:
  step: 9
  weight: 0.05
---

# Skill: Remediation Guidance

## Input
JSON with: vulnerabilities (id, title, cwe_id, severity, affected_component, remediation)

## Task
For each vulnerability:
1. Write immediate fix (quick mitigation to stop the bleeding)
2. Write long-term fix (proper architectural solution)
3. Provide actual code examples for both fixes
4. Estimate implementation effort (Low/Medium/High)
5. Assign priority: P0 (immediate), P1 (this week), P2 (this month)
6. List verification steps to confirm the fix works
7. Provide rollback plan in case the fix breaks something
8. Suggest automated tests to prevent regression

## Output Format
```json
{
  "remediation_plan": [
    {
      "vuln_id": "VULN-2026-001",
      "title": "...",
      "priority": "P0",
      "effort": "Low",
      "immediate_fix": {"description": "...", "code": {"language": "nginx", "code": "..."}},
      "long_term_fix": {"description": "...", "steps": ["1. ...", "2. ..."]},
      "verification": ["curl command with expected result"],
      "rollback_plan": "How to revert if fix breaks something",
      "regression_tests": ["Test case description to prevent recurrence"]
    }
  ],
  "summary": {"total_fixes": 0, "p0_immediate": 0, "p1_this_week": 0, "p2_this_month": 0, "estimated_total_effort": "..."}
}
```

## Success Criteria
- Every vulnerability has both immediate and long-term fix
- Code examples must be syntactically valid
- Verification steps must be copy-pasteable commands with expected results
- Priority: P0 for critical/high, P1 for medium, P2 for low
- Effort estimate must be realistic
- Rollback plan included
- Regression tests suggested
- Output must be valid JSON
