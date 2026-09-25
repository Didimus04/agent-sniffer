"""
pipeline/auditor.py — Auditor Agent Consolidation Module (Req 2.5)
Aggregates prior agent findings, computes CVSSv3 score & final Severity, and builds ThreatReport.
"""
from __future__ import annotations

from shared.models import ThreatReport, Signal


def max_severity(severities: list[str]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 2}
    return max(severities, key=lambda s: order.get(s.lower(), 1))


def build_remediation(scan_signals: list[Signal], red_findings: dict) -> str:
    if not scan_signals and not red_findings.get("gemini_summary"):
        return "No threats detected. Code is clean."
    reasons = [s.description for s in scan_signals]
    if red_findings.get("gemini_summary"):
        reasons.append(str(red_findings["gemini_summary"]))
    return "; ".join(reasons)


def consolidate(
    parsed: dict,
    scan_signals: list[Signal],
    red_findings: dict,
) -> ThreatReport:
    """Consolidate all findings into ThreatReport (Req 2.5)."""
    sevs = [s.severity for s in scan_signals] if scan_signals else ["low"]
    severity = max_severity(sevs)

    if red_findings.get("sandbox", {}).get("malicious"):
        severity = "critical"

    return ThreatReport(
        severity=severity,
        matched_patterns=[s.pattern_id for s in scan_signals],
        remediation_summary=build_remediation(scan_signals, red_findings),
        signals=scan_signals,
        agent_chain=["Parser", "Scanner", "RedTeamer", "Auditor"],
    )
