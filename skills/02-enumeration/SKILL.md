---
name: 02-enumeration
description: "Analyze subdomain enumeration and directory discovery results to identify high-value targets, exposed admin panels, and sensitive paths"
license: MIT
metadata:
  step: 2
  weight: 0.10
---

# Skill: Enumeration Analysis

## Input

A JSON object containing:
- `target`: The target domain
- `subdomains`: Array of discovered subdomains with HTTP status, title, and IP
- `directories`: Array of discovered directories with status code and size

## Task

1. Classify each subdomain by risk level (high/medium/low) based on naming and status
2. Identify high-value targets: admin panels, dev/staging environments, APIs, git repositories
3. Flag subdomains returning 200 on sensitive paths (/.git, /admin, /backup, /.env)
4. Identify directory listing enabled (response size > 1000 on / with 200)
5. Flag exposed sensitive files (.env, .git/config, backup.sql, web.config)
6. Rank subdomains by likelihood of containing vulnerabilities

## Output Format

```json
{
  "high_value_targets": [
    {
      "host": "admin.example.com",
      "reason": "Admin panel accessible without authentication",
      "risk": "high",
      "url": "https://admin.example.com",
      "title": "Admin Login"
    }
  ],
  "sensitive_paths": [
    {
      "host": "example.com",
      "path": "/.git/config",
      "status": 200,
      "risk": "critical",
      "reason": "Git repository exposed — may leak source code and credentials"
    }
  ],
  "subdomain_ranking": [
    {"host": "admin.example.com", "score": 9, "reason": "Admin panel"},
    {"host": "dev.example.com", "score": 7, "reason": "Development environment"},
    {"host": "api.example.com", "score": 8, "reason": "API endpoint"}
  ],
  "summary": "Found 3 high-value targets. Git repository exposed on main domain. Admin panel accessible on admin subdomain."
}
```

## Success Criteria

- All subdomains with admin/dev/api/staging in name must be classified as high or medium risk
- Exposed .git, .env, backup files must be flagged as critical
- Subdomain ranking must include a numeric score (1-10) and reason
- No false positives (e.g., 404 responses should not be flagged as sensitive)
- Output must be valid JSON matching the schema above
