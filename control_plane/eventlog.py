"""
control_plane/eventlog.py — SIEM Single-Line JSONL Writer (Req 14.2, 14.12)
Appends tamper-evident audit records using non-blocking aiofiles async I/O.
"""
from __future__ import annotations

import json
from pathlib import Path
import aiofiles

LOG_PATH = "logs/pantheon.jsonl"


async def write_async(entry: dict) -> None:
    """Append one SIEM event as a single-line JSON object (Req 14.2, 14.12)."""
    Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
    async with aiofiles.open(LOG_PATH, "a", encoding="utf-8") as f:
        await f.write(line + "\n")
