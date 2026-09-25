"""
pipeline/static_scanner.py — Scanner Agent SAST & CPG/GNN Module (Req 3.1–3.6, 4.1–4.6)
Executes Semgrep pattern SAST and Joern CPG + GNN data-flow anomaly detection.
"""
from __future__ import annotations

import json
import subprocess
from shared.models import Signal

JOERN_TIMEOUT_S = 20


def parse_semgrep_json(stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout)
        results = data.get("results", [])
        return [
            {
                "severity": r.get("extra", {}).get("severity", "WARNING").lower(),
                "rule_id": r.get("check_id", "semgrep_rule"),
                "message": r.get("extra", {}).get("message", "Semgrep rule match"),
            }
            for r in results
        ]
    except Exception:
        return []


def semgrep_scan(artifact: dict, rule_sets: list[str]) -> list[Signal]:
    """Pattern SAST. Non-zero exit → inconclusive, pipeline continues (Req 3.5, Prop 6)."""
    target_path = artifact.get("path", "")
    if not target_path:
        return []
    try:
        proc = subprocess.run(
            ["semgrep", "--json", "--config", *rule_sets, target_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            return [
                Signal(
                    severity="medium",
                    pattern_id="semgrep_error",
                    source="semgrep",
                    confidence=0.0,
                    description="inconclusive: semgrep exit != 0",
                )
            ]
        matches = parse_semgrep_json(proc.stdout)
        return [
            Signal(
                severity=m["severity"],
                pattern_id=m["rule_id"],
                source="semgrep",
                confidence=1.0,
                description=m["message"],
            )
            for m in matches
        ]
    except Exception as exc:
        return [
            Signal(
                severity="medium",
                pattern_id="semgrep_exception",
                source="semgrep",
                confidence=0.0,
                description=f"inconclusive: {exc}",
            )
        ]


def cpg_gnn_scan(artifact: dict, gnn: object, threshold: float = 0.75) -> list[Signal]:
    """Data-flow anomaly via Joern CPG + GNN. Timeout → Semgrep-only (Req 4.5, Prop 7)."""
    lang = artifact.get("language", "").lower()
    if lang not in ("python", "javascript", "typescript", "java"):
        return []
    target_path = artifact.get("path", "")
    if not target_path:
        return []
    try:
        cpg = subprocess.run(
            ["joern", "--script", "cpg.sc", target_path],
            capture_output=True,
            text=True,
            timeout=JOERN_TIMEOUT_S,
        )
        score: float = getattr(gnn, "infer", lambda x: 0.0)(cpg.stdout)
        if score > threshold:
            return [
                Signal(
                    severity="high",
                    pattern_id="gnn_anomaly",
                    source="gnn",
                    confidence=score,
                    description=f"data-flow anomaly score {score:.2f}",
                )
            ]
    except (subprocess.TimeoutExpired, Exception):
        return []
    return []
