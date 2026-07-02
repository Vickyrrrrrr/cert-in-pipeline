---
name: 02-enumeration
description: "Subdomain discovery, directory fuzzing, API endpoint discovery, vhost enumeration, JS file analysis, cloud asset discovery"
license: MIT
metadata:
  step: 2
  weight: 0.10
---

# Skill: Enumeration Analysis

## Input
JSON with: target, subdomains (host, ip, status, title), directories (path, status, size)

## Task
1. Classify each subdomain by risk (high/medium/low) based on naming and status
2. Identify high-value targets: admin, dev, staging, api, git, jenkins, grafana, kibana
3. Flag exposed sensitive files: .git, .env, .svn, backup.sql, web.config, .DS_Store
4. Identify exposed config files: config.php, wp-config.php, application.properties
5. Detect API endpoints: /api/, /graphql, /v1/, /v2/, /swagger, /openapi
6. Check for exposed dashboards: /admin, /dashboard, /phpmyadmin, /manager
7. Identify JavaScript files that may contain API keys or endpoints
8. Check for cloud assets: S3 buckets, Azure blobs, Firebase URLs
9. Detect version control exposure: .git/HEAD, .svn/entries, .hg/store
10. Rank subdomains by likelihood of containing vulnerabilities

## Output Format
```json
{
  "high_value_targets": [
    {"host": "admin.example.com", "reason": "Admin panel accessible", "risk": "high", "url": "https://admin.example.com"}
  ],
  "sensitive_paths": [
    {"host": "example.com", "path": "/.git/config", "status": 200, "risk": "critical", "reason": "Git repo exposed"}
  ],
  "api_endpoints": [
    {"url": "/api/v1/users", "method": "GET", "auth_required": "unknown"}
  ],
  "exposed_dashboards": [
    {"url": "/phpmyadmin", "title": "phpMyAdmin"}
  ],
  "js_files": [
    {"url": "/js/app.js", "size": 50000, "may_contain_keys": true}
  ],
  "cloud_assets": [
    {"type": "s3", "url": "https://s3.amazonaws.com/target-backups", "public": "unknown"}
  ],
  "subdomain_ranking": [
    {"host": "admin.example.com", "score": 9, "reason": "Admin panel"}
  ],
  "summary": "Found X high-value targets, Y sensitive paths, Z API endpoints"
}
```

## Success Criteria
- All admin/dev/api/staging subdomains classified as high/medium risk
- Exposed .git, .env, backup files flagged as critical
- API endpoints (/api/, /graphql, /swagger) identified
- Exposed dashboards (phpmyadmin, grafana, jenkins) flagged
- JS files noted for potential key leakage
- No false positives (404 responses should not be flagged)
- Output must be valid JSON
