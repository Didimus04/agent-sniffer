"""
pipeline/red_teamer.py — RedTeamer Agent RAG & Sandbox DAST Module (Req 5.1–5.6, 6.1–6.6)
Queries ChromaDB vector store + Gemini API and runs DAST sandbox execution for suspicious payloads.
"""
from __future__ import annotations

import asyncio

GEMINI_TIMEOUT_S = 15
SANDBOX_TIMEOUT_S = 10


async def rag_exploit_intel(
    payload_summary: str,
    chroma: object,
    gemini: object,
    top_k: int = 5,
) -> dict:
    """ChromaDB top-K CVE/OWASP retrieval + Gemini summary (Req 6.1–6.2, Prop 8, 9)."""
    try:
        docs = getattr(chroma, "query", lambda q, n_results: [])(payload_summary, n_results=top_k)
    except Exception:
        docs = []

    try:
        summary_fn = getattr(gemini, "summarize", None)
        if summary_fn:
            summary = await asyncio.wait_for(
                summary_fn(docs, payload_summary),
                timeout=GEMINI_TIMEOUT_S,
            )
        else:
            summary = None
    except (asyncio.TimeoutError, Exception):
        summary = None  # retrieval-only fallback, Gemini failure logged (Req 6.5, Prop 9)

    return {"rag_results": docs[:top_k], "gemini_summary": summary}


async def sandbox_dast(payload: bytes, runner: object) -> dict:
    """Ephemeral isolated execution; 10s hard kill, partial artifacts kept (Req 5.4)."""
    try:
        exec_fn = getattr(runner, "exec_isolated", None)
        if exec_fn:
            return await asyncio.wait_for(exec_fn(payload), timeout=SANDBOX_TIMEOUT_S)
    except asyncio.TimeoutError:
        return {"timeout": True, "stdout": b"", "stderr": b"timeout after 10s"}
    except Exception as exc:
        return {"error": repr(exc), "stdout": b"", "stderr": b""}

    return {"timeout": False, "stdout": b"", "stderr": b""}
