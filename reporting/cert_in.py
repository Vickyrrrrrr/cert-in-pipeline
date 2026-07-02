"""CERT-In report formatter — converts pipeline results to CERT-In submission format."""

import json
from datetime import datetime
from pathlib import Path


class CertInFormatter:
    """Formats pipeline results into CERT-In vulnerability disclosure report."""

    def __init__(self, reporter_name: str = "", reporter_email: str = "", 
                 submission_email: str = "vdisclose@cert-in.org.in",
                 policy_url: str = "https://www.cert-in.org.in/RVDCP.jsp"):
        self.reporter_name = reporter_name
        self.SUBMISSION_EMAIL = submission_email
        self.POLICY_URL = policy_url
        self.reporter_email = reporter_email

    def format_report(self, report_data: dict, target: str) -> dict:
        """Format the step 08 report output into final CERT-In submission."""

        vulns = report_data.get("vulnerabilities", [])

        submission = {
            "report_metadata": {
                "report_id": f"RPT-{datetime.now().strftime('%Y%m%d')}-{target.replace('.', '-')}",
                "report_date": datetime.now().strftime("%Y-%m-%d"),
                "reporter": {
                    "name": self.reporter_name or "[RESEARCHER NAME]",
                    "email": self.reporter_email or "[RESEARCHER EMAIL]",
                },
                "submission_email": self.SUBMISSION_EMAIL,
                "pgp_recommended": True,
                "policy_url": self.POLICY_URL,
            },
            "target_info": report_data.get("target_info", {"website": target}),
            "executive_summary": report_data.get("executive_summary", ""),
            "vulnerability_summary": report_data.get("vulnerability_summary", {}),
            "vulnerabilities": vulns,
            "disclosure_timeline": report_data.get("disclosure_timeline", {}),
            "cert_in_notes": {
                "cna": "CERT-In is a CVE Numbering Authority and can assign CVE IDs",
                "process": "CERT-In will examine and validate the vulnerability report per RVDCP policy",
                "contact": self.SUBMISSION_EMAIL,
            },
        }

        return submission

    def to_email(self, report: dict) -> str:
        """Generate a plain text email body for CERT-In submission."""

        meta = report.get("report_metadata", {})
        vulns = report.get("vulnerabilities", [])
        summary = report.get("vulnerability_summary", {})

        email_body = f"""To: {self.SUBMISSION_EMAIL}
Subject: Vulnerability Disclosure Report — {meta.get('report_id', '')}

Dear CERT-In Team,

Please find below a vulnerability disclosure report submitted in accordance with the Responsible Vulnerability Disclosure and Coordination Policy (RVDCP).

Report ID: {meta.get('report_id', '')}
Report Date: {meta.get('report_date', '')}
Reporter: {meta.get('reporter', {}).get('name', '')} <{meta.get('reporter', {}).get('email', '')}>

--- EXECUTIVE SUMMARY ---

{report.get('executive_summary', '')}

--- VULNERABILITY SUMMARY ---

Total: {summary.get('total', 0)}
Critical: {summary.get('critical', 0)}
High: {summary.get('high', 0)}
Medium: {summary.get('medium', 0)}
Low: {summary.get('low', 0)}

--- VULNERABILITIES ---

"""

        for i, v in enumerate(vulns, 1):
            email_body += f"""
[{i}] {v.get('title', 'Untitled')}
    ID: {v.get('id', '')}
    CWE: {v.get('cwe', '')} — {v.get('cwe_name', '')}
    CVSS: {v.get('cvss_vector', '')} ({v.get('cvss_score', '')} — {v.get('severity', '')})
    Affected: {v.get('affected_component', '')}

    Description:
    {v.get('description', '')}

    Impact:
    {v.get('impact', '')}

    Reproduction:
"""
            for step in v.get('reproduction_steps', []):
                email_body += f"    {step}\n"

            email_body += f"""
    Proof of Concept:
    {v.get('poc', '')}

    Remediation:
    {v.get('remediation', '')}

    References:
"""
            for ref in v.get('references', []):
                email_body += f"    - {ref}\n"

            email_body += "\n" + "-" * 60 + "\n"

        email_body += """
--- DISCLOSURE TIMELINE ---

"""
        timeline = report.get("disclosure_timeline", {}).get("proposed_timeline", [])
        for t in timeline:
            email_body += f"Day {t.get('day', '?')}: {t.get('action', '')}\n"

        email_body += f"""
---
This report is submitted in good faith for coordinated vulnerability disclosure.
Please acknowledge receipt and advise on next steps.

PGP encryption is recommended for sensitive communications.

Reference: {self.POLICY_URL}

Regards,
{meta.get('reporter', {}).get('name', '')}
"""

        return email_body

    def save_report(self, report: dict, output_dir: str, target: str) -> list[str]:
        """Save report in multiple formats (JSON + email text)."""

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        safe_target = target.replace(".", "-")
        json_path = out / f"cert-in-report-{safe_target}.json"
        email_path = out / f"cert-in-email-{safe_target}.txt"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        with open(email_path, "w", encoding="utf-8") as f:
            f.write(self.to_email(report))

        return [str(json_path), str(email_path)]
