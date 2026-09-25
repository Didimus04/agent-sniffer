"""
sdk/forensics.py — ForensicExtractor Module (Req 15.1, 15.2, 16.1–16.4)
Transforms raw CodeChunk into safe-to-transmit SubmissionPayload.
Applies PII redaction, EvidenceHash SHA-256, line coordinates, and memory cleanup.
"""
from __future__ import annotations

import ast
import hashlib
import re
import subprocess
from pathlib import Path

from shared.models import CodeChunk, ForensicContext, SubmissionPayload
from sdk.path_index import derive_identity

# ── Masking Rules (Req 13.4, 16.2) ──────────────────────────────────────────

_MASKING_RULES: list[tuple[str, str]] = [
    (
        r'(?i)(password|secret|api_key|token|auth_token)\s*=\s*["\']?([^"\';\s]+)["\']?',
        r'\1=[REDACTED:CREDENTIAL]',
    ),
    (r'\b[A-Za-z0-9+/]{32,}={0,2}\b', '[REDACTED:BASE64]'),
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', '[REDACTED:CARD]'),
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED:EMAIL]'),
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED:SSN]'),
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mask(text: str) -> str:
    """Apply all PII redaction rules; return sanitized source text (Req 16.2)."""
    result = text
    for pattern, replacement in _MASKING_RULES:
        result = re.sub(pattern, replacement, result)
    return result


def _evidence_hash(source_text: str) -> str:
    """SHA-256 of original unmasked source — computed BEFORE any masking (Req 16.3)."""
    return hashlib.sha256(source_text.encode("utf-8")).hexdigest()


def _git_commit_hash(file_path: str) -> str | None:
    """Last git commit hash that touched this file. None if unavailable (Req 16.1)."""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H", "--", file_path],
            capture_output=True,
            text=True,
            timeout=3,
        )
        value = result.stdout.strip()
        return value if value else None
    except Exception:
        return None


def _line_coordinates(file_source: str, function_name: str) -> dict[str, int | None]:
    """Extract start/end line numbers of a named function via AST (Req 16.1)."""
    try:
        tree = ast.parse(file_source)
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function_name
            ):
                return {"start": node.lineno, "end": node.end_lineno}
    except Exception:
        pass
    return {"start": None, "end": None}


# ── Public Entry Point ───────────────────────────────────────────────────────

def extract(
    chunk: CodeChunk,
    file_path: str,
    file_source: str,
    client_id: str,
    anchor: str = ".",
) -> SubmissionPayload:
    """
    Transform CodeChunk into safe SubmissionPayload (Req 15.1, 15.2).
    Deletes chunk.source_text and file_source from memory immediately after extraction.
    """
    source_text: str = chunk.source_text  # local reference before deletion

    # 1. Zero-Knowledge Path Privacy Identity
    identity = derive_identity(file_path, anchor=anchor)

    # 2. Line coordinates & Git commit hash
    coords = _line_coordinates(file_source, chunk.function_name)
    commit = _git_commit_hash(file_path)

    # 3. Evidence hash (MUST be computed BEFORE masking, Req 16.3)
    ev_hash = _evidence_hash(source_text)

    # 4. Masked payload
    masked = _mask(source_text)

    # 5. Memory cleanup (Req 15.1, 16.6)
    del source_text
    del file_source
    chunk.source_text = ""  # clear reference on the chunk object

    # 6. Assemble ForensicContext & SubmissionPayload
    forensic = ForensicContext(
        file_path_hash=identity.file_path_hash,
        relative_masked_path=identity.relative_masked_path,
        line_coordinates=coords,
        git_commit_hash=commit,
    )

    return SubmissionPayload(
        file_path_hash=identity.file_path_hash,
        relative_masked_path=identity.relative_masked_path,
        function_name=chunk.function_name,
        match_reason=chunk.match_reason,
        asset_owner_role=chunk.asset_owner_role,
        client_id=client_id,
        forensic_context=forensic,
        masked_payload=masked,
        evidence_hash=ev_hash,
    )
