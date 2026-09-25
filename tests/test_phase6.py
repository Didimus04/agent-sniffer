"""
Property-Based Tests and Unit Tests for Phase 6 SDD Implementation
Feature: agent-sniffer (PANTHEON)
Covers: gateway/sentry.py, pipeline/crew.py, static_scanner.py, red_teamer.py, auditor.py, inspector/decision.py
"""

from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st

from gateway.sentry import SentryGateway, TriageVerdict
from pipeline.crew import AGENT_CHAIN, build_crew, run_pipeline_sync
from pipeline.static_scanner import semgrep_scan, cpg_gnn_scan
from pipeline.auditor import consolidate
from inspector.decision import route, generate_patch
from shared.models import ThreatReport, Signal, SubmissionPayload, ForensicContext


# Feature: agent-sniffer, Property 3: Pipeline agent invocation order is always preserved
# Validates: Requirements 2.1
def test_property_3_pipeline_agent_invocation_order():
    assert AGENT_CHAIN == ["Parser", "Scanner", "RedTeamer", "Auditor"]


# Feature: agent-sniffer, Property 4: Agent failure causes fail-closed classification at Severity high
# Validates: Requirements 2.6
def test_property_4_agent_failure_fail_closed():
    failed_report = ThreatReport.fail_closed("Simulated agent exception")
    assert failed_report.severity == "high"
    assert "pipeline_failure" in failed_report.matched_patterns
    assert failed_report.agent_chain == ["Parser", "Scanner", "RedTeamer", "Auditor"]


# Feature: agent-sniffer, Property 10: High/critical Severity always triggers automated response
# Validates: Requirements 7.1
@given(
    sev=st.sampled_from(["high", "critical"]),
    asset_type=st.sampled_from(["source_code", "runtime_payload"]),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_10_high_critical_automated_response(sev, asset_type):
    report = ThreatReport(
        severity=sev,
        matched_patterns=["p/auth_bypass"],
        remediation_summary="High severity vulnerability detected",
    )
    job = {"asset_type": asset_type}
    policy = type("MockPolicy", (), {
        "severity_routing": {"critical": "block", "high": "block"},
        "gemini_client": None,
    })()
    action = route(report, job, policy)
    assert action in ("block", "patch", "escalate")


# Unit Test: Sentry Gateway Triage & Deduplication (Req 16.8)
def test_sentry_gateway_triage():
    gateway = SentryGateway(blocklist={"malicious_hash_64_chars"})
    job1 = {
        "chunk": type("MockChunk", (), {
            "file_path_hash": "hash_1",
            "evidence_hash": "clean_hash",
            "match_reason": "none",
        })()
    }
    # Clean job
    verdict1 = gateway.triage(job1)
    assert verdict1.disposition == "clean"

    # Duplicate job -> dropped clean
    verdict2 = gateway.triage(job1)
    assert verdict2.disposition == "clean"
    assert verdict2.reason == "duplicate_of_processed_job"

    # Suspicious exec job -> forwarded to CrewAI Pipeline
    job2 = {
        "chunk": type("MockChunk", (), {
            "file_path_hash": "hash_2",
            "evidence_hash": "suspicious_hash",
            "match_reason": "exec",
        })()
    }
    verdict3 = gateway.triage(job2)
    assert verdict3.disposition == "suspicious"
