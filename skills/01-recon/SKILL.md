---
name: 01-recon
description: "Analyze initial reconnaissance data (DNS, SSL, headers, WHOIS) for a target website and identify the technology stack, potential attack surface, and notable misconfigurations"
license: MIT
metadata:
  step: 1
  weight: 0.10
---

# Skill: Reconnaissance Analysis

## Input

A JSON object containing:
- `target`: The target domain or URL
- `dns`: DNS records (A, MX, TXT, CNAME, NS)
- `ssl`: SSL certificate details (issuer, validity, SAN entries)
- `headers`: HTTP response headers from the target
- `whois`: WHOIS registration data

## Task

Analyze the reconnaissance data and produce an attack surface assessment:

1. Identify all technologies and versions from headers, SSL, and DNS
2. Flag any outdated or vulnerable software versions
3. Check SSL configuration for weaknesses (expired, self-signed, weak cipher)
4. Identify security headers that are missing (CSP, HSTS, X-Frame-Options, etc.)
5. Note any DNS misconfigurations (open SPF, missing DMARC, dangling CNAME)
6. Summarize the attack surface in plain language

## Output Format

Return a JSON object with this exact structure:

```json
{
  "technologies": [
    {"name": "nginx", "version": "1.24.0", "category": "web-server"}
  ],
  "security_headers": {
    "present": ["X-Content-Type-Options"],
    "missing": ["Content-Security-Policy", "Strict-Transport-Security"],
    "weak": ["X-Frame-Options: ALLOW-FROM *"]
  },
  "ssl_issues": ["Certificate expires in 10 days"],
  "dns_issues": ["No DMARC record found"],
  "attack_surface_summary": "The target runs nginx 1.24.0 with PHP 8.2. Missing CSP and HSTS headers increase exposure to XSS and MITM attacks. SSL certificate is valid but expires soon.",
  "recommendations": ["Add Content-Security-Policy header", "Enable HSTS", "Set up DMARC record"]
}
```

## Success Criteria

- All technologies from headers and SSL must be identified
- All missing security headers from OWASP secure headers project must be flagged
- SSL issues must include expiry within 30 days, self-signed, or weak algorithms
- DNS issues must check for SPF, DMARC, and dangling CNAME records
- Attack surface summary must be specific to the target (not generic)
- Output must be valid JSON matching the schema above
