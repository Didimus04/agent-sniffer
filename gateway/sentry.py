"""
gateway/sentry.py — Sentry Gateway (Req 16.8)
Pure-Python entry-point triage and deduplication on the FastAPI server.
Performs fast deterministic triage without LLM calls or agent frameworks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class TriageVerdict:
    disposition: Literal["clean", "suspicious"]
    reason: str


class SentryGateway:
    """Entry-point triage on Pipeline Worker (Req 16.8). Deterministic, zero LLM cost."""

    def __init__(self, blocklist: set[str] | None = None) -> None:
        self._seen: set[tuple[str, str]] = set()  # (file_path_hash, evidence_hash)
        self._blocklist = blocklist or set()

    def triage(self, job: dict) -> TriageVerdict:
        """Triage job or batch of jobs. Returns clean (release) or suspicious (forward to CrewAI)."""
        chunk = job.get("chunk")
        if not chunk and job.get("chunks"):
            # Handle BatchedSubmissionPayload array (Req 15.11)
            chunks = job["chunks"]
            for c in chunks:
                v = self._triage_single(c)
                if v.disposition == "suspicious":
                    return v
            return TriageVerdict("clean", "all_batched_chunks_clean")
        elif chunk:
            return self._triage_single(chunk)
        return TriageVerdict("clean", "no_chunk_data")

    def _triage_single(self, chunk: object) -> TriageVerdict:
        file_path_hash = getattr(chunk, "file_path_hash", "")
        evidence_hash = getattr(chunk, "evidence_hash", "")
        match_reason = getattr(chunk, "match_reason", "")

        key = (file_path_hash, evidence_hash)
        if key in self._seen:
            return TriageVerdict("clean", "duplicate_of_processed_job")
        self._seen.add(key)

        if evidence_hash in self._blocklist:
            return TriageVerdict("suspicious", "evidence_blocklist_hit")

        if match_reason in ("exec", "crypto", "auth", "suspicious_low_entropy_paywall", "ics_anomaly", "force_sandbox_hrd"):
            return TriageVerdict("suspicious", f"critical_match:{match_reason}")

        return TriageVerdict("clean", "no_triage_signal")
