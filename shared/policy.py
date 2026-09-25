"""
shared/policy.py — Operator Policy Configuration for PANTHEON
Loaded from YAML/JSON at startup; validated via Pydantic; hot-reloaded within 5 seconds.
"""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field, field_validator


class SemgrepConfig(BaseModel):
    rule_sets: list[str] = Field(
        default=["p/default"],
        description="Local file paths or Semgrep Registry identifiers.",
    )


class GNNConfig(BaseModel):
    model_path: str = "models/gnn_default.pt"
    anomaly_threshold: float = Field(default=0.75, ge=0.0, le=1.0)


class ChromaDBConfig(BaseModel):
    collection_name: str = "threat_intel"
    persist_directory: str = ".chromadb"
    top_k: int = Field(default=5, ge=1, le=50)


class GeminiConfig(BaseModel):
    api_key: str = "placeholder_key"
    model: str = "gemini-1.5-flash"
    rpm_limit: int = Field(default=14, ge=1, le=60)
    timeout_seconds: int = Field(default=15, ge=1)


class HVPProfileConfig(BaseModel):
    role: str
    severity_weight: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    priority_multiplier: float = Field(ge=1.0, le=5.0)
    threat_vectors: list[str] = Field(default_factory=list)
    monitored_assets: list[str] = Field(default_factory=list)
    escalation_channels: list[str] = Field(default_factory=list)
    auto_escalation_threshold: float = Field(default=9.0, ge=9.0, le=10.0)
    email_patterns: list[str] = Field(default_factory=list)
    path_patterns: list[str] = Field(default_factory=list)


class ScanQueueConfig(BaseModel):
    maxsize: int = Field(default=1_000, ge=100, le=10_000)
    worker_count: int = Field(default=3, ge=1, le=20)


class ServerQueueConfig(BaseModel):
    maxsize: int = Field(default=5_000, ge=100, le=50_000)
    worker_count: int = Field(default=3, ge=1, le=20)


class SeverityRoutingConfig(BaseModel):
    critical: Literal["block", "patch", "escalate"] = "block"
    high: Literal["block", "patch", "escalate"] = "block"
    medium: Literal["block", "patch", "escalate"] = "escalate"
    low: Literal["block", "patch", "escalate"] = "block"


class FailModeConfig(BaseModel):
    on_inspector_error: Literal["fail_open", "fail_closed"] = "fail_closed"
    on_oversized_payload: Literal["block", "allow", "truncate"] = "block"
    max_payload_bytes: int = Field(default=32_768, ge=1_024)


class SessionConfig(BaseModel):
    ttl_seconds: int = Field(default=3_600, ge=60)
    super_admin_key_bits: int = Field(default=512, ge=512)
    admin_key_bits: int = Field(default=256, ge=256)


class EscalationConfig(BaseModel):
    timeout_seconds: int = Field(default=60, ge=5)
    default_action: Literal["block", "allow"] = "block"


class AuditLogConfig(BaseModel):
    output: Literal["file", "stdout", "both"] = "both"
    log_file_path: str = "logs/pantheon.jsonl"
    verbose: bool = False
    max_buffer_entries: int = Field(default=10_000, ge=1_000)


class Policy(BaseModel):
    """Root Policy configuration. Loaded from YAML or JSON at startup."""

    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    gnn: GNNConfig = Field(default_factory=GNNConfig)
    chromadb: ChromaDBConfig = Field(default_factory=ChromaDBConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    hvp_profiles: list[HVPProfileConfig] = Field(default_factory=list)
    scan_queue: ScanQueueConfig = Field(default_factory=ScanQueueConfig)
    server_queue: ServerQueueConfig = Field(default_factory=ServerQueueConfig)
    severity_routing: SeverityRoutingConfig = Field(default_factory=SeverityRoutingConfig)
    fail_mode: FailModeConfig = Field(default_factory=FailModeConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    escalation: EscalationConfig = Field(default_factory=EscalationConfig)
    audit_log: AuditLogConfig = Field(default_factory=AuditLogConfig)

    code_extension_allowlist: list[str] = Field(
        default=[".py", ".js", ".ts", ".go", ".cpp", ".c", ".java", ".rs"]
    )
    trusted_domains: list[str] = Field(
        default_factory=list,
        description="Trusted org domains for HVP_CALENDAR OSINT check.",
    )
    url_allowlist: list[str] = Field(
        default_factory=list,
        description="Trusted external URLs; suppresses data exfiltration signal.",
    )

    @field_validator("hvp_profiles")
    @classmethod
    def _unique_roles(cls, profiles: list[HVPProfileConfig]) -> list[HVPProfileConfig]:
        roles = [p.role for p in profiles]
        if len(roles) != len(set(roles)):
            raise ValueError("hvp_profiles: duplicate role entries are not allowed")
        return profiles
