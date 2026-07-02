---
name: 03-port-scan
description: "Port scanning, service detection, firewall evasion, UDP services, service-specific vulnerabilities, cloud metadata"
license: MIT
metadata:
  step: 3
  weight: 0.10
---

# Skill: Port Scan Analysis

## Input
JSON with: hosts (ip, hostname, ports with port, state, service, version, os)

## Task
1. List all open ports and services with versions
2. Flag services that should NOT be internet-exposed: MySQL, Redis, MongoDB, Elasticsearch, Memcached, RDP, SMB, Docker, Kubernetes API
3. Identify outdated versions with known CVEs
4. Check for services on non-standard ports (SSH on 2222, HTTP on 8080/8443)
5. Identify potential attack vectors based on exposed services
6. Check for cloud metadata service (169.254.169.254) if cloud-hosted
7. Detect databases exposed without authentication
8. Identify remote management services: RDP, VNC, TeamViewer, Webmin
9. Check for container orchestration: Docker API, Kubernetes API, Mesos
10. Flag message queue services: RabbitMQ, Kafka, ActiveMQ

## Output Format
```json
{
  "exposed_services": [{"host": "1.2.3.4", "port": 22, "service": "ssh", "version": "OpenSSH 8.9p1", "risk": "medium"}],
  "dangerous_exposures": [{"host": "1.2.3.4", "port": 3306, "service": "mysql", "risk": "critical"}],
  "outdated_versions": [{"host": "1.2.3.4", "port": 80, "service": "nginx", "version": "1.18.0", "known_cves": ["CVE-2021-23017"]}],
  "non_standard_ports": [{"port": 2222, "service": "ssh", "expected": 22}],
  "remote_management": [{"port": 3389, "service": "rdp", "risk": "high"}],
  "container_services": [{"port": 2375, "service": "docker", "risk": "critical"}],
  "attack_vectors": ["Specific attack vectors based on findings"],
  "recommendations": ["Specific actionable recommendations"]
}
```

## Success Criteria
- All internet-facing database/cache services flagged as critical
- Services with known CVEs identified with CVE IDs
- Non-standard ports noted
- Docker/K8s API flagged as critical if exposed
- Cloud metadata endpoint checked
- Recommendations must be specific (actual config changes)
- Output must be valid JSON
