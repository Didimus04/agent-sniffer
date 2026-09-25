"""
Property-Based Tests and Unit Tests for sdk/pre_filter.py and sdk/ics_parser.py
Feature: agent-sniffer (PANTHEON)
"""

from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st
import tempfile
import pathlib

from sdk.pre_filter import pre_filter, FilterResult, EXCLUDED_FOLDERS, EXCLUDED_EXTENSIONS
from sdk.ics_parser import parse_ics, ICSParseResult


# Feature: agent-sniffer, Property 11: Pre-filter excludes all paths containing excluded folder names
# Validates: Requirements 9.1
@given(
    folder=st.sampled_from(list(EXCLUDED_FOLDERS)),
    filename=st.text(min_size=1, max_size=20).map(lambda s: f"{s}.py"),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_11_pre_filter_excluded_folders(folder, filename):
    path = f"/project/{folder}/{filename}"
    res = pre_filter(path)
    assert not res.passed
    assert res.skip_reason == "excluded_folder"


# Feature: agent-sniffer, Property 12: Pre-filter excludes all paths with excluded extensions
# Validates: Requirements 9.1
@given(
    ext=st.sampled_from(list(EXCLUDED_EXTENSIONS)),
    basename=st.text(min_size=1, max_size=20).map(lambda s: f"file_{s}"),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_12_pre_filter_excluded_extensions(ext, basename):
    path = f"/project/src/{basename}{ext}"
    res = pre_filter(path)
    assert not res.passed
    assert res.skip_reason == "excluded_extension"


# Unit Test: ICS Bypass Gateway and Parser (Ambiguitas 6, Req 9.8)
def test_ics_parser_clean_and_anomaly():
    clean_ics = (
        "BEGIN:VCALENDAR\r\n"
        "BEGIN:VEVENT\r\n"
        "SUMMARY:Team Sync\r\n"
        "ORGANIZER:mailto:admin@corp.com\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR"
    )
    clean_res = parse_ics(clean_ics, trusted_domains=["corp.com"])
    assert not clean_res.external_anomaly
    assert clean_res.initial_context_score == 0.0

    evil_ics = (
        "BEGIN:VCALENDAR\r\n"
        "BEGIN:VEVENT\r\n"
        "SUMMARY:Urgent Action Required\r\n"
        "DESCRIPTION:Verify account at http://evil.com/login\r\n"
        "ORGANIZER:mailto:hacker@external.org\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR"
    )
    evil_res = parse_ics(evil_ics, trusted_domains=["corp.com"])
    assert evil_res.external_anomaly
    assert evil_res.initial_context_score > 0.0
    assert any("url:" in f for f in evil_res.flags)
    assert any("organizer:" in f for f in evil_res.flags)


# Unit Test: HRD Force Sandbox Protocol (Ambiguitas 7, Req 10.6)
def test_hrd_force_sandbox_protocol():
    with tempfile.NamedTemporaryFile(suffix=".pdf", mode="w", delete=False) as f:
        f.write("Resume content for applicant")
        f_path = f.name

    try:
        res = pre_filter(f_path, asset_owner_role="HRD_RECRUITMENT")
        assert res.passed
        assert len(res.chunks) == 1
        assert res.chunks[0].match_reason == "force_sandbox_hrd"
        assert res.chunks[0].function_name == "<document_raw>"
    finally:
        pathlib.Path(f_path).unlink(missing_ok=True)
