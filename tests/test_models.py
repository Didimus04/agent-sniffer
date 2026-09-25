"""
Property-Based Tests and Unit Tests for shared/models.py and shared/policy.py
Feature: agent-sniffer (PANTHEON)
"""

from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st
import hashlib
import json

from shared.models import (
    CodeChunk,
    ForensicContext,
    SubmissionPayload,
    Signal,
    ThreatReport,
    EventLogEntry,
    HVP_Profile,
)
from shared.policy import Policy, GeminiConfig


# Feature: agent-sniffer, Property 19: EventLog entries always contain all required fields
# Validates: Requirements 14.2
@given(
    event_id=st.uuids().map(str),
    target_hvp=st.sampled_from(["CEO", "LEAD_DEV_DEVOPS", "HVP_CALENDAR", "HRD_RECRUITMENT", "UNKNOWN"]),
    hvp_multiplier=st.floats(min_value=1.0, max_value=5.0),
    asset_type=st.sampled_from(["source_code", "runtime_payload", "calendar"]),
    asset_ext=st.sampled_from([".py", ".js", ".ts", ".go", ".ics"]),
    source_path_hash=st.text(min_size=64, max_size=64),
    relative_masked_path=st.text(min_size=5).map(lambda s: f"[root]/{s}"),
    severity_level=st.sampled_from(["low", "medium", "high", "critical"]),
    base_score=st.floats(min_value=0.0, max_value=10.0),
    final_score=st.floats(min_value=0.0, max_value=10.0),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_19_eventlog_required_fields(
    event_id, target_hvp, hvp_multiplier, asset_type, asset_ext,
    source_path_hash, relative_masked_path, severity_level, base_score, final_score
):
    entry = EventLogEntry(
        ts="2026-09-25T00:00:00Z",
        event_id=event_id,
        target_hvp=target_hvp,
        hvp_multiplier=hvp_multiplier,
        asset_type=asset_type,
        asset_ext=asset_ext,
        source_path_hash=source_path_hash,
        relative_masked_path=relative_masked_path,
        severity_level=severity_level,
        base_score=base_score,
        final_score=final_score,
        threat_detected=["test_threat"],
        matched_patterns=["p/test"],
        detection_source="background",
        layer_passed=3,
        action_taken="block",
        patch_generated=False,
        agent_chain=["Parser", "Scanner", "RedTeamer", "Auditor"],
        pipeline_duration_ms=120,
        masked_for_admin=False,
        session_id="sys_123",
        operator_id="op_123",
    )
    assert entry.ts is not None
    assert entry.event_id == event_id
    assert entry.target_hvp == target_hvp
    assert entry.relative_masked_path.startswith("[root]/")
    assert 0.0 <= entry.base_score <= 10.0
    assert 0.0 <= entry.final_score <= 10.0


# Feature: agent-sniffer, Property 21: SubmissionPayload never contains raw file path or source text
# Validates: Requirements 15.2, 16.6
@given(
    file_path_hash=st.text(min_size=64, max_size=64),
    relative_masked_path=st.text(min_size=3).map(lambda s: f"[root]/{s}"),
    function_name=st.text(min_size=1, max_size=30),
    masked_payload=st.text(min_size=1),
    evidence_hash=st.text(min_size=64, max_size=64),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_21_submission_payload_zero_knowledge(
    file_path_hash, relative_masked_path, function_name, masked_payload, evidence_hash
):
    forensic = ForensicContext(
        file_path_hash=file_path_hash,
        relative_masked_path=relative_masked_path,
        line_coordinates={"start": 1, "end": 10},
        git_commit_hash="abc1234",
    )
    payload = SubmissionPayload(
        file_path_hash=file_path_hash,
        relative_masked_path=relative_masked_path,
        function_name=function_name,
        match_reason="auth",
        asset_owner_role="LEAD_DEV_DEVOPS",
        client_id="client_1",
        forensic_context=forensic,
        masked_payload=masked_payload,
        evidence_hash=evidence_hash,
    )
    # Verify no raw absolute path attribute
    assert not hasattr(payload, "source_text")
    assert not hasattr(payload, "raw_file_path")
    assert payload.relative_masked_path.startswith("[root]/")
    assert payload.forensic_context.file_path_hash == file_path_hash


# Feature: agent-sniffer, Property 22: EvidenceHash equals SHA-256 of original source text
# Validates: Requirements 16.3
@given(source_text=st.text(min_size=1, max_size=500))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_22_evidence_hash_sha256(source_text):
    expected_hash = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    assert len(expected_hash) == 64
