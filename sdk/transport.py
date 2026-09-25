"""
sdk/transport.py — Async HTTP Submission Client (Req 15.3–15.7)
Delivers SubmissionPayload from SDK → Control Plane endpoint (POST /api/v1/jobs).
Manages connection pool (max 10), token bucket rate limiter (14 RPM), and HTTP 429/503 backoff retries.
"""
from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import dataclass

import httpx

from shared.models import SubmissionPayload


# ── Custom Exceptions ─────────────────────────────────────────────────────────

class ChunkSubmitTimeout(Exception):
    def __init__(self, payload: SubmissionPayload) -> None:
        self.payload = payload


class RateLimitError(Exception):
    def __init__(self, retry_after: int = 60) -> None:
        self.retry_after = retry_after


class CapacityError(Exception):
    pass


# ── Token Bucket Rate Limiter (Req 15.7) ───────────────────────────────────────

class TokenBucket:
    """Async token bucket — enforces max N calls per minute."""

    def __init__(self, rpm: int = 14) -> None:
        self._interval = 60.0 / rpm   # seconds between tokens
        self._last_call: float = 0.0

    async def acquire(self) -> None:
        now = asyncio.get_event_loop().time()
        wait = self._interval - (now - self._last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call = asyncio.get_event_loop().time()


# ── Transport Client ──────────────────────────────────────────────────────────

class ChunkTransport:
    """Async HTTP client for SDK → Control Plane submission (Req 15.3, 15.7)."""

    def __init__(
        self,
        control_plane_url: str,
        api_key: str,
        rpm_limit: int = 14,
    ) -> None:
        self._url = f"{control_plane_url.rstrip('/')}/api/v1/jobs"
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self._rate_limiter = TokenBucket(rpm=rpm_limit)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=10,
            ),
        )

    async def submit(self, payload: SubmissionPayload) -> str:
        """Submit one SubmissionPayload; return job_id. Non-blocking (Req 15.3)."""
        await self._rate_limiter.acquire()

        body = dataclasses.asdict(payload)

        try:
            response = await self._client.post(
                self._url,
                json=body,
                headers=self._headers,
            )
        except httpx.TimeoutException:
            raise ChunkSubmitTimeout(payload)

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(retry_after=retry_after)

        if response.status_code == 503:
            raise CapacityError()

        response.raise_for_status()
        return response.json()["job_id"]

    async def aclose(self) -> None:
        await self._client.aclose()


# ── SDK Worker Integration ────────────────────────────────────────────────────

async def submit_with_retry(
    transport: ChunkTransport,
    payload: SubmissionPayload,
    scan_queue: asyncio.Queue,
) -> str | None:
    """
    Submit payload; re-queue on recoverable errors (Req 15.5, 15.6).
    Returns job_id on success, None if re-queued.
    """
    try:
        job_id = await transport.submit(payload)
        return job_id

    except ChunkSubmitTimeout:
        await scan_queue.put(payload)
        await asyncio.sleep(5)
        return None

    except RateLimitError as e:
        await scan_queue.put(payload)
        await asyncio.sleep(e.retry_after)
        return None

    except CapacityError:
        await scan_queue.put(payload)
        await asyncio.sleep(30)
        return None
