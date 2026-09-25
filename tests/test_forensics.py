"""
Property-Based Tests and Unit Tests for sdk/forensics.py and sdk/path_index.py
Feature: agent-sniffer (PANTHEON)
"""

from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st
import tempfile
import pathlib
import os

from shared.models import CodeChunk
from sdk.forensics import extract, _mask, _evidence_hash
from sdk.path_index import LocalPathIndex, derive_identity, PathIdentity


# Feature: agent-sniffer, Property 16: Data masking removes all sensitive patterns
# Validates: Requirements 13.4, 16.2
@given(
    secret_val=st.text(min_size=8, max_size=30).filter(lambda s: "\n" not in s and "'" not in s and '"' not in s),
    card_num=st.text(min_size=16, max_size=16).filter(lambda s: s.isdigit()),
    email_user=st.text(min_size=3, max_size=10).filter(lambda s: s.isalnum()),
    email_domain=st.text(min_size=3, max_size=10).filter(lambda s: s.isalnum()),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_16_data_masking_regex(secret_val, card_num, email_user, email_domain):
    raw_text = (
        f"api_key='{secret_val}'\n"
        f"card = '{card_num}'\n"
        f"user_email = '{email_user}@{email_domain}.com'\n"
    )
    masked = _mask(raw_text)
    # Verify no raw sensitive patterns remain
    assert secret_val not in masked or "[REDACTED:CREDENTIAL]" in masked
    assert card_num not in masked or "[REDACTED:CARD]" in masked
    assert f"{email_user}@{email_domain}.com" not in masked or "[REDACTED:EMAIL]" in masked


# Feature: agent-sniffer, Property 24: Detached Metadata Indexing derives display path [root]/...
# Validates: Requirements 15.2, 15.8, 15.9
def test_property_24_path_index_detached_metadata():
    with tempfile.TemporaryDirectory() as tmpdir:
        anchor = tmpdir
        sub_folder = os.path.join(tmpdir, "src")
        os.makedirs(sub_folder, exist_ok=True)
        abs_file = os.path.join(sub_folder, "auth.py")
        with open(abs_file, "w") as f:
            f.write("def login(): pass")

        index_db = os.path.join(tmpdir, "paths.db")
        index = LocalPathIndex(index_db)

        identity = index.register(abs_file, anchor=anchor)
        assert identity.relative_masked_path == "[root]/src/auth.py"
        assert len(identity.file_path_hash) == 64

        # Verify inverse resolution works locally
        resolved_abs = index.resolve_local(identity.file_path_hash)
        assert resolved_abs == abs_file


# Unit Test: ForensicExtractor extract() workflow and memory cleanup (Req 15.1, 16.4)
def test_forensic_extractor_extraction_and_cleanup():
    code_source = "def login():\n    password = 'SuperSecretPassword123'\n    return True\n"
    chunk = CodeChunk(
        file_path_hash="dummy_hash_64_chars_long_dummy_hash_64_chars_long_dummy_hash_64",
        function_name="login",
        source_text=code_source,
        match_reason="auth",
        asset_owner_role="LEAD_DEV_DEVOPS",
        client_id="client_test",
    )

    payload = extract(
        chunk=chunk,
        file_path="/local/machine/src/auth.py",
        file_source=code_source,
        client_id="client_test",
        anchor="/local/machine",
    )

    # 1. Verify SubmissionPayload structure
    assert payload.client_id == "client_test"
    assert payload.relative_masked_path == "[root]/src/auth.py"
    assert payload.masked_payload != code_source
    assert "[REDACTED:CREDENTIAL]" in payload.masked_payload
    assert len(payload.evidence_hash) == 64
    assert payload.evidence_hash == _evidence_hash(code_source)

    # 2. Verify ForensicContext contains no absolute raw path on the payload
    assert payload.forensic_context.relative_masked_path == "[root]/src/auth.py"
    assert payload.forensic_context.line_coordinates == {"start": 1, "end": 3}

    # 3. Verify memory cleanup (chunk.source_text cleared)
    assert chunk.source_text == ""
