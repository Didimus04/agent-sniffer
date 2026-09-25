"""
hvp/matcher.py — HVP Contextual Validator & Threat Intelligence Multiplier (Req 10.1–10.12)
CVSSv3 score scaling, Zero Trust UNKNOWN_HIGH_RISK fallback, and role-specific protocols.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

SUPPLY_CHAIN_BOOST = 1.2
VECTOR_BOOST = 2.0  # CVSSv3 points
CVSS_MAX = 10.0
UNKNOWN_HIGH_RISK_SCORE_FLOOR = 7.0  # CVSSv3 high (Zero Trust, Req 10.9)


def severity_from_score(score: float) -> str:
    """CVSSv3 severity mapping: 0.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass
class MatchResult:
    final_score: float
    severity_weight: str
    targeted_asset_hit: bool
    escalate: bool
    channels: list[str]
    force_sandbox: bool = False
    identity_resolved: bool = True
    zero_trust_escalation: bool = False


def resolve_role(
    forensic_email: str | None,
    file_path: str,
    profiles: list,
) -> object | None:
    """
    Resolve HVP profile via git author email hash -> path pattern -> None.
    Zero Trust: None means UNKNOWN_HIGH_RISK, never low risk (Req 10.9).
    """
    for profile in profiles:
        if forensic_email and any(p in forensic_email for p in profile.email_patterns):
            return profile
        if any(p in file_path for p in profile.path_patterns):
            return profile
    return None  # caller MUST handle None as UNKNOWN_HIGH_RISK


def apply_matcher(
    base_score: float,
    threat_vector: str,
    profile: object | None,
    monitored_hit: bool,
    supply_chain_hit: bool = False,
) -> MatchResult:
    """
    Apply HVP priority multiplier and confidence boost on CVSSv3 scale (0.0-10.0).
    Zero Trust: profile is None -> UNKNOWN_HIGH_RISK, base_score floor 7.0 (Req 10.9).
    """
    if profile is None:  # UNKNOWN_HIGH_RISK fallback (Req 10.9)
        final = max(base_score, UNKNOWN_HIGH_RISK_SCORE_FLOOR)
        final = round(min(final, CVSS_MAX), 1)
        sev = severity_from_score(final)
        return MatchResult(
            final_score=final,
            severity_weight=sev,
            targeted_asset_hit=False,
            escalate=final >= 9.0,
            channels=["control_plane"],
            force_sandbox=False,
            identity_resolved=False,
            zero_trust_escalation=True,
        )

    final = base_score * getattr(profile, "priority_multiplier", 1.0)
    threat_vectors = getattr(profile, "threat_vectors", [])
    if threat_vector in threat_vectors:
        final = min(final + VECTOR_BOOST, CVSS_MAX)

    role = getattr(profile, "role", "UNKNOWN")
    if role == "LEAD_DEV_DEVOPS" and supply_chain_hit:
        final = min(final * SUPPLY_CHAIN_BOOST, CVSS_MAX)

    final = round(min(final, CVSS_MAX), 1)
    auto_thresh = getattr(profile, "auto_escalation_threshold", 9.0)
    channels = list(getattr(profile, "escalation_channels", []))

    return MatchResult(
        final_score=final,
        severity_weight=severity_from_score(final),
        targeted_asset_hit=monitored_hit,
        escalate=final >= auto_thresh,
        channels=channels,
        force_sandbox=role == "HRD_RECRUITMENT",
        identity_resolved=True,
        zero_trust_escalation=False,
    )


def email_sha256(email: str) -> str:
    """Hash git author email — raw email is NEVER stored in logs or payloads (Req 10.11)."""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()
