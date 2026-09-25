"""
shared/models.py — Formal Data Models for PANTHEON (agent-sniffer)
Single source of truth for payload structures across SDK, pipeline, SIEM logging, and Control Plane.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CodeChunk:
    """Unit of analysis produced by pre_filter Layer 3."""
    file_path_hash: str
    function_name: str
    source_text: str          # deleted by ForensicExtractor after use
    match_reason: str
    asset_owner_role: str = "UNKNOWN"
    client_id: str = ""


@dataclass
class ForensicContext:
    """Metadata extracted at SDK side for chain-of-custody (Zero-Knowledge Privacy)."""
    file_path_hash: str                        # SHA-256 of absolute path
    relative_masked_path: str                 # [root]/<relative-path>
    line_coordinates: dict[str, int | None]    # {"start": int, "end": int}
    git_commit_hash: str | None = None


@dataclass
class SubmissionPayload:
    """Safe-to-transmit payload from SDK → Control Plane (Zero-Knowledge Privacy)."""
    file_path_hash: str          # SHA-256(original_file_path)
    relative_masked_path: str    # [root]/...
    function_name: str
    match_reason: str
    asset_owner_role: str
    client_id: str
    forensic_context: ForensicContext
    masked_payload: str          # source with sensitive values redacted
    evidence_hash: str           # SHA-256(original source_text)
    # raw source_text and raw absolute file_path are NEVER included


@dataclass
class Signal:
    """A single detected threat indicator."""
    severity: str                # "low" | "medium" | "high" | "critical"
    pattern_id: str              # Semgrep rule ID or "gnn_anomaly"
    source: str                  # "semgrep" | "gnn" | "rag" | "sandbox"
    confidence: float            # [0.0, 1.0]
    description: str


@dataclass
class ThreatReport:
    """Final output of the four-agent CrewAI pipeline."""
    severity: str
    matched_patterns: list[str]
    remediation_summary: str
    signals: list[Signal] = field(default_factory=list)
    agent_chain: list[str] = field(default_factory=lambda: ["Parser", "Scanner", "RedTeamer", "Auditor"])
    pipeline_duration_ms: int = 0
    patch_diff: str | None = None
    affected_file_path_hash: str = ""
    cve_reference: str | None = None
    patch_source: str | None = None     # "gemini" | "template" | None

    @classmethod
    def fail_closed(cls, reason: str, duration_ms: int = 0) -> ThreatReport:
        """Fail-closed fallback classification at Severity high (Req 2.6)."""
        return cls(
            severity="high",
            matched_patterns=["pipeline_failure"],
            remediation_summary=f"Fail-closed execution: {reason}",
            agent_chain=["Parser", "Scanner", "RedTeamer", "Auditor"],
            pipeline_duration_ms=duration_ms,
        )


@dataclass
class EventLogEntry:
    """SIEM-compatible single-line JSON log record (Req 14.2)."""
    ts: str
    event_id: str
    target_hvp: str
    hvp_multiplier: float
    asset_type: str
    asset_ext: str
    source_path_hash: str
    relative_masked_path: str
    severity_level: str
    base_score: float           # CVSSv3 0.0-10.0
    final_score: float          # CVSSv3 0.0-10.0
    threat_detected: list[str]
    matched_patterns: list[str]
    detection_source: str        # "perimeter" | "background"
    layer_passed: int
    action_taken: str
    patch_generated: bool
    agent_chain: list[str]
    pipeline_duration_ms: int
    masked_for_admin: bool
    session_id: str
    operator_id: str
    forensic_context: ForensicContext | None = None
    masked_payload: str | None = None
    evidence_hash: str | None = None
    encrypted_payload: bytes | None = None  # AES-256, SUPER_ADMIN only
    identity_resolved: bool = True
    zero_trust_escalation: bool = False


@dataclass
class SeverityChangeRequest:
    """Pending severity downgrade — requires SUPER_ADMIN approval (Req 13.6)."""
    request_id: str
    signal_id: str
    original_severity: str
    requested_severity: str
    requesting_admin_id: str
    reason: str
    status: str                  # "pending_approval" | "approved" | "rejected"
    created_at: str
    resolved_at: str | None = None
    resolved_by: str | None = None


@dataclass
class HVP_Profile:
    """Risk profile for a High-Value Person role."""
    role: str
    severity_weight: str
    priority_multiplier: float
    threat_vectors: list[str] = field(default_factory=list)
    monitored_assets: list[str] = field(default_factory=list)
    escalation_channels: list[str] = field(default_factory=list)
    auto_escalation_threshold: float = 9.0  # CVSSv3, hardcoded >= 9.0
    email_patterns: list[str] = field(default_factory=list)
    path_patterns: list[str] = field(default_factory=list)
