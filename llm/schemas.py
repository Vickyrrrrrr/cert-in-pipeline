"""Pydantic schemas for structured agent output — the #1 hallucination guard.

Every agent MUST output a validated Pydantic model. The OpenAI Agents SDK
won't finalize a run until the schema passes, so the LLM is forced to
produce structured, evidence-bound findings instead of free-text hallucination.
"""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    """A single vulnerability finding — evidence-bound, no free-text escape."""

    id: str = Field(description="Unique ID like F-001")
    title: str = Field(description="Short title, e.g. 'Exposed Admin Panel'")
    severity: Severity = Field(description="critical|high|medium|low|info")
    cwe: str | None = Field(default=None, description="CWE-XXX identifier")
    owasp: str | None = Field(default=None, description="OWASP category")
    cvss_score: float = Field(ge=0, le=10, description="CVSS 3.1 score")
    cvss_vector: str | None = Field(default=None, description="CVSS:3.1/AV:...")
    affected_component: str = Field(description="Which host/port/path")
    description: str = Field(description="What the vulnerability is")
    impact: str = Field(description="What an attacker can do")
    evidence_ref: str = Field(description="ID into evidence store (ev_XXX)")
    discovery_method: str = Field(description="How it was discovered")
    discovery_commands: list[str] = Field(default_factory=list, description="Exact shell commands")
    poc: str = Field(description="Reproducible curl/command to verify")
    poc_expected_result: str = Field(description="What you should see when running the PoC")
    remediation: str = Field(description="Specific fix recommendation")
    verified: bool = Field(default=False, description="Whether a Verifier agent confirmed this")


class ReconOutput(BaseModel):
    """Output schema for the Recon agent."""

    subdomains: list[str] = Field(default_factory=list, description="Discovered subdomains")
    live_hosts: list[dict] = Field(default_factory=list, description="Live HTTP hosts with status+title")
    open_ports: list[dict] = Field(default_factory=list, description="Open ports with service+version")
    technologies: list[str] = Field(default_factory=list, description="Detected tech stack")
    dns_records: list[dict] = Field(default_factory=list, description="DNS records found")
    summary: str = Field(description="Brief summary of attack surface")


class EnumOutput(BaseModel):
    """Output schema for the Enumeration agent."""

    directories: list[dict] = Field(default_factory=list, description="Discovered paths with status codes")
    api_endpoints: list[str] = Field(default_factory=list, description="Discovered API endpoints")
    sensitive_files: list[str] = Field(default_factory=list, description="Exposed sensitive files (.git, .env, etc.)")
    high_value_targets: list[str] = Field(default_factory=list, description="Targets worth deeper scanning")
    summary: str = Field(description="Brief summary of enumeration findings")


class VulnOutput(BaseModel):
    """Output schema for the Vulnerability Scanner agent."""

    findings: list[Finding] = Field(default_factory=list, description="Raw findings from scanning")
    templates_run: int = Field(default=0, description="Number of nuclei templates executed")
    summary: str = Field(description="Brief summary of scan results")


class VerifiedFinding(BaseModel):
    """Output of the Verifier agent — a finding that has been independently confirmed."""

    finding_id: str = Field(description="Original finding ID")
    verified: bool = Field(description="True if the PoC was successfully reproduced")
    verification_output: str = Field(description="What the verifier observed")
    false_positive: bool = Field(default=False, description="True if this is a false positive")
    adjusted_severity: Severity | None = Field(default=None, description="Corrected severity if different")


class ScanReport(BaseModel):
    """Final report — the only thing the user sees."""

    target: str = Field(description="Primary target domain")
    scan_timestamp: str = Field(description="ISO 8601 timestamp")
    executive_summary: str = Field(description="Plain-English summary for management")
    targets_scanned: list[str] = Field(default_factory=list, description="All hosts/subdomains scanned")
    scan_commands_used: list[str] = Field(default_factory=list, description="All commands for reproducibility")
    vulnerability_summary: dict = Field(default_factory=dict, description="Count by severity")
    vulnerabilities: list[Finding] = Field(default_factory=list, description="Only VERIFIED findings")
    remediation_priority: list[str] = Field(default_factory=list, description="Ordered fix recommendations")
    cert_in_references: list[str] = Field(default_factory=list, description="CERT-In advisory references")


class CoordinatorHandoff(BaseModel):
    """What the coordinator passes to the reporter."""

    raw_findings: list[Finding] = Field(default_factory=list)
    verified_findings: list[VerifiedFinding] = Field(default_factory=list)
    recon_summary: str = Field(default="")
    enum_summary: str = Field(default="")
    vuln_summary: str = Field(default="")
    targets_scanned: list[str] = Field(default_factory=list)
    commands_used: list[str] = Field(default_factory=list)
