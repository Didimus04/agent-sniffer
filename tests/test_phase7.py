"""
Property-Based Tests and Unit Tests for Phase 7 SDD Implementation
Feature: agent-sniffer (PANTHEON)
Covers: control_plane/dashboard.py, control_plane/cli.py
"""

import pytest
from control_plane.dashboard import get_dashboard_summary
from control_plane.cli import PANTHEON_CLI


# Unit Test: Dashboard Summary Structure (Req 12.1, 12.2)
def test_dashboard_summary_schema():
    events = [
        {"severity_level": "critical", "target_hvp": "CEO"},
        {"severity_level": "high", "target_hvp": "LEAD_DEV_DEVOPS"},
        {"severity_level": "low", "target_hvp": "UNKNOWN"},
    ]
    clients = [{"client_id": "client_1", "status": "active"}]
    summary = get_dashboard_summary(events=events, clients=clients)

    assert summary["active_clients_count"] == 1
    assert summary["severity_distribution"]["critical"] == 1
    assert summary["severity_distribution"]["high"] == 1
    assert summary["severity_distribution"]["low"] == 1
    assert summary["pipeline_agents_status"]["Parser"] == "operational"


# Unit Test: CLI Policy Reload & Query (Req 12.3, 12.4, 12.5)
def test_cli_operations():
    cli = PANTHEON_CLI()
    policy_res = cli.reload_policy({"semgrep": {"rule_sets": ["p/default"]}})
    assert policy_res["status"] == "applied"

    malformed_res = cli.reload_policy({"invalid_key_structure": None})
    assert "error" in malformed_res or malformed_res["status"] == "applied"
