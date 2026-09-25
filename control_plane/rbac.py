"""
control_plane/rbac.py — Session Token & Role Validation (Req 13.10–13.14)
Issues & validates HMAC-SHA256 SessionTokens using in-memory signing keys.
Enforces SUPER_ADMIN and ADMIN RBAC boundaries at FastAPI dependency level.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Annotated

from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ── Signing Keys (generated once at startup, in-memory only, Req 13.13) ───────

ROLE_SIGNING_KEYS: dict[str, bytes] = {
    "SUPER_ADMIN": secrets.token_bytes(64),   # 512-bit
    "ADMIN":       secrets.token_bytes(32),   # 256-bit
}

# ── In-memory session store (Req 13.10) ───────────────────────────────────────

SESSION_STORE: dict[str, dict] = {}

# ── SDK API keys (loaded from Policy at startup) ──────────────────────────────
SDK_API_KEYS: set[str] = {"placeholder_key"}

security = HTTPBearer()


# ── Token Issuance (Req 13.10) ────────────────────────────────────────────────

def create_session_token(
    user_id: str,
    role: str,
    ttl_seconds: int = 3_600,
) -> dict:
    """Issue HMAC-SHA256 signed SessionToken. In-memory keys only (Req 13.10, 13.13)."""
    if role not in ROLE_SIGNING_KEYS:
        raise ValueError(f"Unknown role: {role}")

    session_id = secrets.token_hex(32)
    issued_at = int(time.time())
    expires_at = issued_at + ttl_seconds

    payload = f"{session_id}:{user_id}:{role}:{issued_at}:{expires_at}"
    signature = hmac.new(
        ROLE_SIGNING_KEYS[role],
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    SESSION_STORE[session_id] = {
        "user_id": user_id,
        "role": role,
        "expires_at": expires_at,
        "signature": signature,
    }

    return {
        "session_token": f"{payload}:{signature}",
        "expires_at": expires_at,
    }


# ── Token Validation (Req 13.11, 13.12) ───────────────────────────────────────

def validate_session_token(token: str) -> dict:
    """Validate token signature & expiry. Returns session dict or raises HTTPException 401."""
    try:
        *payload_parts, provided_sig = token.split(":")
        payload = ":".join(payload_parts)
        session_id, user_id, role, _, expires_at_str = payload_parts
    except (ValueError, IndexError):
        raise HTTPException(status_code=401, detail="malformed_token")

    # Expiry check (Req 13.12)
    if int(time.time()) > int(expires_at_str):
        raise HTTPException(status_code=401, detail="token_expired")

    # Role key lookup
    key = ROLE_SIGNING_KEYS.get(role)
    if key is None:
        raise HTTPException(status_code=401, detail="unknown_role")

    # HMAC verification — timing-safe comparison (Req 13.11)
    expected_sig = hmac.new(
        key,
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(status_code=401, detail="invalid_signature")

    # Session store check
    stored = SESSION_STORE.get(session_id)
    if not stored:
        raise HTTPException(status_code=401, detail="session_not_found")

    return {"user_id": user_id, "role": role, "session_id": session_id}


# ── FastAPI Dependencies (Req 13.1, 13.14) ────────────────────────────────────

async def get_current_session(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    return validate_session_token(credentials.credentials)


async def require_super_admin(
    session: dict = Depends(get_current_session),
) -> dict:
    """Enforce SUPER_ADMIN role boundary (Req 13.14)."""
    if session["role"] != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="super_admin_required")
    return session


async def require_any_admin(
    session: dict = Depends(get_current_session),
) -> dict:
    """Enforce SUPER_ADMIN or ADMIN role boundary (Req 13.1)."""
    if session["role"] not in ("SUPER_ADMIN", "ADMIN"):
        raise HTTPException(status_code=403, detail="admin_required")
    return session


async def require_sdk_client(
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Validate SDK API key header (Req 15.3)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_api_key")
    api_key = authorization.removeprefix("Bearer ").strip()
    if api_key not in SDK_API_KEYS:
        raise HTTPException(status_code=401, detail="invalid_api_key")
    return {"api_key": api_key}


# ── Unauthorized Access Logger ────────────────────────────────────────────────

async def log_unauthorized_attempt(
    session_id: str,
    attempted_operation: str,
    eventlog,
) -> None:
    """Log unauthorized access attempts in EventLog (Req 13.14)."""
    await eventlog.write({
        "event_type": "unauthorized_access_attempt",
        "session_id": session_id,
        "attempted_operation": attempted_operation,
    })
