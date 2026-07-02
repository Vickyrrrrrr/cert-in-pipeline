---
name: 09-remediation
description: "Provide specific, actionable remediation guidance with code examples for each confirmed vulnerability"
license: MIT
metadata:
  step: 9
  weight: 0.05
---

# Skill: Remediation Guidance

## Input

A JSON object containing:
- `vulnerabilities`: Array of vulnerabilities from step 08 report
- Each has: id, title, cwe_id, severity, affected_component, remediation (basic)

## Task

For each vulnerability, provide detailed remediation:

1. Write an immediate fix (quick mitigation to stop the bleeding)
2. Write a long-term fix (proper architectural solution)
3. Provide actual code examples for both fixes
4. Estimate implementation effort (Low/Medium/High)
5. Assign priority (P0 = immediate, P1 = this week, P2 = this month)
6. List verification steps to confirm the fix works

## Output Format

```json
{
  "remediation_plan": [
    {
      "vuln_id": "VULN-2026-001",
      "title": "Exposed Git Repository Leaks Source Code",
      "priority": "P0",
      "effort": "Low",
      "immediate_fix": {
        "description": "Block access to .git directory via web server configuration",
        "config": {
          "web_server": "nginx",
          "code": "location ~ /\\.git {\n    deny all;\n    return 404;\n}"
        }
      },
      "long_term_fix": {
        "description": "Ensure .git directory is outside the web root. Use a deployment pipeline that copies only necessary files to the web server.",
        "steps": [
          "Move the git repository outside the web root",
          "Set up a CI/CD pipeline that builds and deploys artifacts",
          "Remove .git from production server entirely"
        ]
      },
      "verification": [
        "Run: curl -s -o /dev/null -w '%{http_code}' https://example.com/.git/config",
        "Expected result: 404",
        "Run: curl -s -o /dev/null -w '%{http_code}' https://example.com/.git/HEAD",
        "Expected result: 404"
      ]
    },
    {
      "vuln_id": "VULN-2026-002",
      "title": "Reflected XSS in search parameter",
      "priority": "P1",
      "effort": "Low",
      "immediate_fix": {
        "description": "Add output encoding for user input in the search template",
        "code": {
          "language": "php",
          "code": "// Before (vulnerable):\necho $_GET['q'];\n\n// After (fixed):\necho htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');"
        }
      },
      "long_term_fix": {
        "description": "Implement a Content Security Policy header and use a templating engine with auto-escaping",
        "config": {
          "web_server": "nginx",
          "code": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;"
        },
        "steps": [
          "Migrate to a templating engine like Twig (PHP) that auto-escapes output",
          "Implement CSP headers across all responses",
          "Add automated XSS testing to CI/CD pipeline"
        ]
      },
      "verification": [
        "Run: curl -s 'https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E' | grep -c 'alert(1)'",
        "Expected result: 0 (payload should be encoded, not present as-is)"
      ]
    }
  ],
  "summary": {
    "total_fixes": 2,
    "p0_immediate": 1,
    "p1_this_week": 1,
    "estimated_total_effort": "Low — both fixes can be implemented in under 4 hours"
  }
}
```

## Success Criteria

- Every vulnerability must have both an immediate fix and a long-term fix
- Code examples must be syntactically valid for the specified language
- Verification steps must be copy-pasteable commands with expected results
- Priority must be P0 for critical/high, P1 for medium, P2 for low
- Effort estimate must be realistic (blocking .git = Low, refactoring auth = High)
- Remediation must be specific to the vulnerability (not generic "update your software")
- Output must be valid JSON matching the schema above
