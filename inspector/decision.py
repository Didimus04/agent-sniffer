"""
inspector/decision.py — Severity Routing & Automation Engine (Req 7.1–7.6, 11.1–11.6, Prop 10)
Maps Auditor ThreatReport Severity to actions: auto-block, auto-patch, hold-escalate, allow.
"""
from __future__ import annotations

from shared.models import ThreatReport


def render_template_patch(matched_patterns: list[str]) -> str:
    """Rule-based remediation template fallback when Gemini API is unavailable (Req 7.6)."""
    lines = ["# Rule-Based Remediation Template Patch (Gemini Offline)", "---"]
    for pattern in matched_patterns:
        lines.append(f"# Fix for pattern: {pattern}")
        lines.append("# Add input validation & sanitize variables")
    return "\n".join(lines)


def generate_patch(report: ThreatReport, policy: object) -> tuple[str | None, str | None]:
    """Generate remediation patch via Gemini API or fallback template (Req 7.3, 7.6)."""
    gemini_client = getattr(policy, "gemini_client", None)
    if gemini_client and hasattr(gemini_client, "patch"):
        try:
            diff = gemini_client.patch(report.matched_patterns)
            return diff, "gemini"
        except Exception:
            pass
    # Fallback to template patch (Req 7.6)
    return render_template_patch(report.matched_patterns), "template"


def route(report: ThreatReport, job: dict, policy: object) -> str:
    """
    Map final Severity to action (Req 7.1–7.5, Prop 10).
    Returns "block" | "patch" | "escalate" | "hold_escalate" | "allow".
    """
    sev = report.severity.lower()
    routing = getattr(policy, "severity_routing", {})

    if sev in ("critical", "high"):
        action = getattr(routing, sev, "block") if hasattr(routing, sev) else routing.get(sev, "block")
        if action == "patch" and job.get("asset_type") == "source_code":
            report.patch_diff, report.patch_source = generate_patch(report, policy)
        return action  # "block" | "patch" | "escalate"

    if sev == "medium":
        return "hold_escalate"  # Hold in Gateway pending queue + escalation

    return "allow"
