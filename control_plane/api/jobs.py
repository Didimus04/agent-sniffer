"""
control_plane/api/jobs.py — Inbound Job Endpoint (Req 15.3, 15.4, 15.10, 15.11)
Receives SubmissionPayload from SDK, enforces per-user rate ceiling (10 RPM),
places jobs onto SERVER_SCAN_QUEUE, and returns job_id within 50ms.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from control_plane.rbac import require_sdk_client
from shared.models import SubmissionPayload

router = APIRouter(prefix="/api/v1", tags=["jobs"])

# Pipeline Worker queue — shared across all workers (Req 15.4)
SERVER_SCAN_QUEUE: asyncio.Queue = asyncio.Queue(maxsize=5_000)

# Per-User Throttling & Suspended Queue Engine (Ambiguitas 10, Req 15.10)
USER_RPM_CEILING: int = 10  # max 10 RPM per user/device signature
USER_TRANSACTIONS: dict[str, list[float]] = {}  # client_id -> timestamps
USER_SUSPENDED_QUEUE: dict[str, asyncio.Queue] = {}  # client_id -> bounded holding queue


def check_and_track_user_rate(client_id: str, limit: int = USER_RPM_CEILING) -> bool:
    """Return True if under rate ceiling, False if burst threshold exceeded."""
    now = datetime.now(timezone.utc).timestamp()
    timestamps = USER_TRANSACTIONS.setdefault(client_id, [])
    # purge timestamps older than 60s
    USER_TRANSACTIONS[client_id] = [t for t in timestamps if now - t < 60.0]
    if len(USER_TRANSACTIONS[client_id]) >= limit:
        return False
    USER_TRANSACTIONS[client_id].append(now)
    return True


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.post("/jobs", status_code=200)
async def receive_job(
    payload: SubmissionPayload,
    _client: dict = Depends(require_sdk_client),
) -> dict:
    """
    Accept a SubmissionPayload from the SDK (Req 15.3).
    Enforces per-user rate ceiling (10 RPM); suspends overflow, returns 429 on burst.
    Returns {job_id, status: "queued"} within 50ms.
    """
    client_id = payload.client_id or payload.file_path_hash

    if not check_and_track_user_rate(client_id):
        # Throttle stream, place into memory-bounded suspended holding queue (Req 15.10)
        holding_queue = USER_SUSPENDED_QUEUE.setdefault(client_id, asyncio.Queue(maxsize=100))
        try:
            holding_queue.put_nowait({"chunk": payload, "submitted_at": utcnow_iso()})
        except asyncio.QueueFull:
            pass  # bound memory, drop if holding queue full
        raise HTTPException(
            status_code=429,
            detail="rate_limit_exceeded",
            headers={"Retry-After": "60"},
        )

    if SERVER_SCAN_QUEUE.full():
        raise HTTPException(status_code=503, detail="queue_full")

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "chunk": payload,
        "submitted_at": utcnow_iso(),
        "client_id": client_id,
    }

    try:
        SERVER_SCAN_QUEUE.put_nowait(job)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="queue_full")

    return {"job_id": job_id, "status": "queued"}
