---
name: 01-recon
description: "Comprehensive reconnaissance: DNS, SSL, HTTP headers, WAF detection, CDN, CORS, tech stack, rate limiting, cloud storage"
license: MIT
metadata:
  step: 1
  weight: 0.10
---

# Skill: Reconnaissance Analysis

## Input
JSON with: target, dns, ssl, headers, whois

## Task
1. Identify ALL technologies and versions from headers, SSL, DNS, cookies
2. Detect WAF/CDN (Cloudflare, AWS WAF, Akamai, Sucuri, Imperva)
3. Check security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
4. Analyze SSL: expiry, self-signed, weak cipher, protocol version, SAN mismatches
5. DNS health: SPF, DMARC, DKIM, dangling CNAME, open DNS recursion
6. Detect CORS configuration: Access-Control-Allow-Origin: * with credentials
7. Identify rate limiting: X-RateLimit headers, Retry-After
8. Check for cloud storage: S3 buckets, Azure blobs, GCP storage referenced in JS
9. Analyze cookies: HttpOnly, Secure, SameSite flags
10. Detect framework-specific leaks: X-Powered-By, X-AspNet-Version

## Output Format
```json
{
  "technologies": [{"name": "nginx", "version": "1.24.0", "category": "web-server"}],
  "waf_detected": {"name": "Cloudflare", "evidence": "cf-ray header"},
  "cdn_detected": {"name": "CloudFront", "evidence": "x-amz-cf-id header"},
  "security_headers": {
    "present": ["X-Content-Type-Options"],
    "missing": ["Content-Security-Policy", "Strict-Transport-Security"],
    "weak": ["X-Frame-Options: ALLOW-FROM *"]
  },
  "ssl_issues": ["Certificate expires in 10 days"],
  "dns_issues": ["No DMARC record", "SPF too permissive (~all)"],
  "cors_issues": ["ACAO: * with ACAC: true — credential leak risk"],
  "cookie_issues": ["PHPSESSID missing HttpOnly flag"],
  "rate_limiting": {"detected": false},
  "cloud_storage": ["https://s3.amazonaws.com/target-backups"],
  "attack_surface_summary": "Specific summary of attack surface",
  "recommendations": ["Specific actionable recommendations"]
}
```

## Success Criteria
- All technologies from headers AND SSL must be identified
- WAF/CDN detection must check for common providers
- All missing OWASP secure headers must be flagged
- CORS misconfiguration must be flagged if ACAO:* with credentials
- Cookie security flags must be checked
- Cloud storage references must be noted if found
- Output must be valid JSON
