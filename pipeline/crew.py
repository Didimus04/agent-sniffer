"""
pipeline/crew.py — CrewAI 4-Agent Pipeline Builder & Runner (Req 2.1–2.7, Prop 3, 4)
Parser Agent → Scanner Agent → RedTeamer Agent → Auditor Agent (AGENT_CHAIN).
"""
from __future__ import annotations

import time
from crewai import Agent, Crew, Process, Task

from shared.models import ThreatReport

PIPELINE_TIMEOUT_S = 30
AGENT_CHAIN = ["Parser", "Scanner", "RedTeamer", "Auditor"]


def build_crew(payload: dict, tools: dict) -> Crew:
    """Four agents, strictly sequential. Each task feeds the next (Req 2.1, Prop 3)."""
    parser = Agent(
        role="Parser",
        goal="Normalize payload encoding and extract AST structure",
        backstory="Expert code parser and AST normalizer.",
        tools=[tools["parse"]] if "parse" in tools else [],
        async_execution=True,
    )
    scanner = Agent(
        role="Scanner",
        goal="Perform SAST pattern scan and CPG/GNN anomaly detection",
        backstory="Static security scanner powered by Semgrep and Joern CPG.",
        tools=[tools["semgrep"], tools["cpg_gnn"]] if "semgrep" in tools else [],
        async_execution=True,
    )
    red = Agent(
        role="RedTeamer",
        goal="Perform RAG exploit threat intelligence and ephemeral DAST sandbox execution",
        backstory="Adversarial security researcher examining payload behavior.",
        tools=[tools["rag"], tools["sandbox"]] if "rag" in tools else [],
        async_execution=True,
    )
    auditor = Agent(
        role="Auditor",
        goal="Consolidate all prior findings into final CVSSv3 ThreatReport",
        backstory="Senior security auditor certifying payload threat severity.",
        async_execution=True,
    )
    tasks = [
        Task(description="parse", agent=parser, expected_output="ParsedArtifact"),
        Task(description="scan", agent=scanner, expected_output="ScanResult"),
        Task(description="redteam", agent=red, expected_output="RedTeamFindings"),
        Task(description="audit", agent=auditor, expected_output="ThreatReport"),
    ]
    return Crew(
        agents=[parser, scanner, red, auditor],
        tasks=tasks,
        process=Process.sequential,
    )


def run_pipeline_sync(job: dict, tools: dict | None = None) -> ThreatReport:
    """
    Sync entry point — always called inside run_in_executor, never on loop.
    Fail-closed: any unhandled exception returns ThreatReport.fail_closed() (Req 2.6, Prop 4).
    """
    started = time.monotonic()
    t_tools = tools or {}
    try:
        crew = build_crew(job.get("chunk", {}), t_tools)
        result = crew.kickoff()
        duration = int((time.monotonic() - started) * 1000)
        return ThreatReport(
            severity=getattr(result, "severity", "low"),
            matched_patterns=getattr(result, "matched_patterns", []),
            remediation_summary=getattr(result, "remediation_summary", "Clean scan"),
            pipeline_duration_ms=duration,
        )
    except Exception as exc:
        duration = int((time.monotonic() - started) * 1000)
        return ThreatReport.fail_closed(reason=repr(exc), duration_ms=duration)
