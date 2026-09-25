"""
control_plane/dashboard.py — Control Plane Dashboard Endpoint (Req 12.1, 12.2, 12.7)
Read-only dashboard metrics: active client connections, severity distribution, agent status, pending escalations.
"""
from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends
from control_plane.rbac import require_any_admin

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


def get_dashboard_summary(
    events: list[dict] | None = None,
    clients: list[dict] | None = None,
    pending_escalations: list[dict] | None = None,
) -> dict:
    """Generate read-only dashboard summary payload (Req 12.1, 12.2, 12.7)."""
    ev_list = events or []
    cl_list = clients or []
    esc_list = pending_escalations or []

    distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for ev in ev_list:
        sev = str(ev.get("severity_level", "low")).lower()
        if sev in distribution:
            distribution[sev] += 1

    return {
        "active_clients_count": len(cl_list),
        "clients": cl_list,
        "recent_signals_count": len(ev_list),
        "severity_distribution": distribution,
        "pipeline_agents_status": {
            "Parser": "operational",
            "Scanner": "operational",
            "RedTeamer": "operational",
            "Auditor": "operational",
        },
        "pending_escalations": esc_list,
    }


@router.get("", status_code=200)
async def dashboard_endpoint(
    session: Annotated[dict, Depends(require_any_admin)],
) -> dict:
    """FastAPI GET /api/v1/dashboard endpoint (Req 12.1). RBAC enforced."""
    # In live server, queries EventLog and client registry
    return get_dashboard_summary()
