"""
sdk/path_index.py — Detached Metadata Indexing (Zero-Knowledge Path Privacy)
Stores local file_path_hash -> absolute_path mapping in SQLite on developer machine.
Wire payloads carry ONLY file_path_hash and relative_masked_path ([root]/...).
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from pydantic import BaseModel, Field


class PathIdentity(BaseModel):
    """Identity material attached to every SubmissionPayload (Req 15.2, Zero-Knowledge)."""
    file_path_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    relative_masked_path: str = Field(pattern=r"^\[root\]/\S+$")


class LocalPathRecord(BaseModel):
    """Machine-local index row. NEVER serialized to the wire (Req 15.8)."""
    file_path_hash: str
    absolute_path: str


def derive_identity(absolute_path: str, anchor: str) -> PathIdentity:
    """Hash + masked display path ([root]/...). Raises ValueError on anchor escape."""
    abs_p = Path(absolute_path).resolve()
    anc_p = Path(anchor).resolve()
    try:
        rel = abs_p.relative_to(anc_p)
    except ValueError:
        rel = Path(abs_p.name)

    if ".." in rel.parts:
        raise ValueError("path escapes anchor")

    return PathIdentity(
        file_path_hash=hashlib.sha256(absolute_path.encode("utf-8")).hexdigest(),
        relative_masked_path="[root]/" + rel.as_posix(),
    )


class LocalPathIndex:
    """Stateful machine-local agent store: hash → absolute path (Req 15.8, 15.9)."""

    def __init__(self, db_path: str = ".pantheon/paths.db") -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._db:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS paths (
                    file_path_hash TEXT PRIMARY KEY,
                    absolute_path TEXT NOT NULL
                )
                """
            )

    def register(self, absolute_path: str, anchor: str = ".") -> PathIdentity:
        """Register local path and return display-safe PathIdentity for wire."""
        identity = derive_identity(absolute_path, anchor)
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO paths (file_path_hash, absolute_path) VALUES (?, ?)",
                (identity.file_path_hash, absolute_path),
            )
        return identity

    def resolve_local(self, file_path_hash: str) -> str | None:
        """Inverse resolution — loopback/local-process only (Req 15.9)."""
        row = self._db.execute(
            "SELECT absolute_path FROM paths WHERE file_path_hash = ?",
            (file_path_hash,),
        ).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        self._db.close()
