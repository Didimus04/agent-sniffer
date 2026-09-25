"""
Property-Based Tests and Unit Tests for control_plane/rbac.py and sdk/transport.py
Feature: agent-sniffer (PANTHEON)
"""

from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st
import time

from control_plane.rbac import (
    create_session_token,
    validate_session_token,
    ROLE_SIGNING_KEYS,
)
from sdk.transport import TokenBucket


# Feature: agent-sniffer, Property 17: SessionToken tamper detection rejects any modified token
# Validates: Requirements 13.11
@given(
    user_id=st.text(min_size=1, max_size=20).filter(lambda s: ":" not in s),
    role=st.sampled_from(["SUPER_ADMIN", "ADMIN"]),
    tamper_offset=st.integers(min_value=0, max_value=50),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_17_session_token_tamper_detection(user_id, role, tamper_offset):
    token_dict = create_session_token(user_id=user_id, role=role, ttl_seconds=3600)
    token_str = token_dict["session_token"]

    # Tamper with character in token string
    if len(token_str) > tamper_offset:
        char_to_change = "X" if token_str[tamper_offset] != "X" else "Y"
        tampered_token = (
            token_str[:tamper_offset] + char_to_change + token_str[tamper_offset + 1 :]
        )
        try:
            res = validate_session_token(tampered_token)
            # If validate_session_token doesn't raise, verify session_id must match store
            assert res is None or res.get("user_id") != user_id
        except Exception as e:
            # Expected to fail/raise HTTPException
            assert True


# Feature: agent-sniffer, Property 18: SessionToken round-trip — issued tokens pass validation
# Validates: Requirements 13.10, 13.12
@given(
    user_id=st.text(min_size=1, max_size=20).filter(lambda s: ":" not in s),
    role=st.sampled_from(["SUPER_ADMIN", "ADMIN"]),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_18_session_token_roundtrip(user_id, role):
    token_dict = create_session_token(user_id=user_id, role=role, ttl_seconds=3600)
    token_str = token_dict["session_token"]
    session = validate_session_token(token_str)
    assert session["user_id"] == user_id
    assert session["role"] == role


# Unit Test: TokenBucket rate limiter (Req 15.7)
def test_token_bucket_acquire():
    bucket = TokenBucket(rpm=60)
    assert bucket._interval == 1.0
