---
name: 03-port-scan
description: "Analyze nmap port scan results to identify open ports, running services, outdated versions, and potential attack vectors"
license: MIT
metadata:
  step: 3
  weight: 0.10
---

# Skill: Port Scan Analysis

## Input

A JSON object containing:
- `hosts`: Array of hosts with their open ports, services, versions, and OS detection

## Task

1. List all open ports and their services with versions
2. Flag any services with known outdated or vulnerable versions
3. Identify services that should not be exposed to the internet (MySQL, Redis, MongoDB, Elasticsearch, RDP, SMB)
4. Check for services running on non-standard ports (e.g., SSH on 2222, HTTP on 8080)
5. Identify potential attack vectors based on exposed services
6. Recommend which services should be firewalled or restricted

## Output Format

```json
{
  "exposed_services": [
    {
      "host": "1.2.3.4",
      "port": 22,
      "service": "ssh",
      "version": "OpenSSH 8.9p1",
      "risk": "medium",
      "notes": "SSH exposed — should use key-based auth only"
    }
  ],
  "dangerous_exposures": [
    {
      "host": "1.2.3.4",
      "port": 3306,
      "service": "mysql",
      "version": "MySQL 8.0.35",
      "risk": "critical",
      "notes": "Database exposed to internet — credential brute-force and exploitation risk"
    }
  ],
  "outdated_versions": [
    {
      "host": "1.2.3.4",
      "port": 80,
      "service": "http",
      "version": "nginx 1.18.0",
      "current": "1.25.3",
      "known_cves": ["CVE-2021-23017", "CVE-2022-41741"],
      "risk": "high"
    }
  ],
  "attack_vectors": [
    "MySQL exposed on port 3306 — potential for SQL injection via direct connection",
    "SSH on port 22 — brute-force attack vector if password auth enabled"
  ],
  "recommendations": [
    "Firewall MySQL port 3306 — restrict to internal network only",
    "Update nginx from 1.18.0 to latest stable version",
    "Disable SSH password authentication, enforce key-based auth"
  ]
}
```

## Success Criteria

- All internet-facing database/cache services (MySQL, Redis, MongoDB, ES) must be flagged as critical
- Services with known CVEs must be identified with CVE IDs
- Non-standard ports must be noted
- Attack vectors must be specific to the services found (not generic)
- Recommendations must be actionable (specific config changes, not "update your software")
- Output must be valid JSON matching the schema above
