"""
control_plane/ws/routing.py — Role-Filtered WebSocket Broadcast Targets (Req 14.5–14.8, Prop 20)
Determines recipient roles per event severity and target HVP.
"""
from __future__ import annotations


def ws_targets(entry: dict) -> set[str]:
    """
    Return recipient roles for WebSocket delivery.
    CEO-targeted events (high/critical/medium) NEVER reach ADMIN connections (Req 14.6, Prop 20).
    """
    sev = entry.get("severity_level")
    hvp = entry.get("target_hvp")

    if sev in ("high", "critical"):
        return {"SUPER_ADMIN"} if hvp == "CEO" else {"ADMIN", "SUPER_ADMIN"}

    if sev == "medium":
        # Summary payload push for medium severity (Req 14 AC#7/AC#12)
        return {"SUPER_ADMIN"} if hvp == "CEO" else {"ADMIN", "SUPER_ADMIN"}

    return set()  # low -> EventLog only (Req 14.8)
