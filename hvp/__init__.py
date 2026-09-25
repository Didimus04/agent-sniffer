"""
hvp/identity.py — GPG Commit Signature Verification & Grace Period (Req 10.13–10.15)
Verifies commit GPG signatures for CRITICAL/HIGH HVP assets;
implements Cryptographic Key Lifecycle Grace Period (WARM LOCK & bootstrap token).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import subprocess
import time
from dataclasses import dataclass

_BOOTSTRAP_KEY: bytes = secrets.token_bytes(32)  # in-memory only, rotated per startup
_VERIFY_TIMEOUT_S = 5
_GATED_WEIGHTS = frozenset({"CRITICAL", "HIGH"})
_GRACE_HOURS_DEFAULT = 72  # Req 10.15


@dataclass
class IdentityVerdict:
    is_spoofed: bool
    reason: str | None = None
    # reason "warm_lock" -> Grace Period: hold at MEDIUM (Pending Key Verification),
    # commit flagged WARM LOCK in EventLog, bootstrap token issued (Req 10.14-10.15).
    detail: dict | None = None


def issue_bootstrap_token(
    author_email_hash: str,
    git_commit_hash: str,
    grace_hours: int = _GRACE_HOURS_DEFAULT,
) -> str:
    """Issue HMAC-signed key-rotation bootstrap token (Req 10.14)."""
    expiry = time.time() + (grace_hours * 3,600)
    payload = f"{author_email_hash}:{git_commit_hash}:{expiry}"
    sig = hmac.new(_BOOTSTRAP_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_commit_identity(
    git_commit_hash: str | None,
    severity_weight: str,
    author_email_hash: str | None = None,
    employee_directory: object | None = None,
    grace_hours: int = 72,
) -> IdentityVerdict:
    """
    GPG-verify commit signature for CRITICAL/HIGH HVP assets (Req 10.13).
    If untrusted/expired key AND author email is in internal employee directory:
    hold at MEDIUM, apply WARM LOCK, issue bootstrap token (Grace Period, Req 10.14-10.15).
    """
    if severity_weight not in _GATED_WEIGHTS:
        return IdentityVerdict(is_spoofed=False)

    if not git_commit_hash:
        return IdentityVerdict(is_spoofed=True, reason="no_signature")

    try:
        result = subprocess.run(
            ["git", "verify-commit", git_commit_hash],
            capture_output=True,
            text=True,
            timeout=_VERIFY_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return IdentityVerdict(is_spoofed=True, reason="timeout")
    except (FileNotFoundError, OSError):
        return IdentityVerdict(is_spoofed=True, reason="git_unavailable")

    if result.returncode == 0:
        return IdentityVerdict(is_spoofed=False)

    stderr = (result.stderr or "").lower()
    if "no signature" in stderr or "not signed" in stderr:
        reason = "no_signature"
    elif "expired" in stderr:
        reason = "expired_key"
    elif "can't check signature" in stderr or "no public key" in stderr:
        reason = "untrusted_key"
    else:
        reason = "invalid_signature"

    # Cryptographic Key Lifecycle Grace Period (Req 10.14)
    if reason in ("untrusted_key", "expired_key") and employee_directory is not None:
        if author_email_hash and employee_directory.is_known(author_email_hash):
            token = issue_bootstrap_token(author_email_hash, git_commit_hash, grace_hours)
            return IdentityVerdict(
                is_spoofed=False,
                reason="warm_lock",
                detail={"bootstrap_token": token, "grace_hours": grace_hours},
            )

    return IdentityVerdict(is_spoofed=True, reason=reason)
