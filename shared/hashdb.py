"""
shared/hashdb.py — Local SQLite Hash Gate Database (Layer 2)
Stores per-function SHA-256 hashes to skip unchanged functions during background scan.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path


class HashDB:
    """Thread-safe SQLite wrapper for function hash caching (Req 9.2, 9.5)."""

    def __init__(self, db_path: str = ".pantheon/hashdb.sqlite") -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS function_hashes (
                    file_path_hash TEXT NOT NULL,
                    function_name TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (file_path_hash, function_name)
                )
                """
            )

    def get(self, file_path_hash: str, function_name: str) -> str | None:
        """Retrieve stored SHA-256 hash for a given function."""
        cursor = self._conn.execute(
            """
            SELECT sha256 FROM function_hashes
            WHERE file_path_hash = ? AND function_name = ?
            """,
            (file_path_hash, function_name),
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def update(self, file_path_hash: str, function_name: str, sha256: str) -> None:
        """Insert or replace SHA-256 hash for a processed function (Req 9.5)."""
        now = int(time.time())
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO function_hashes (file_path_hash, function_name, sha256, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (file_path_hash, function_name, sha256, now),
            )

    def close(self) -> None:
        self._conn.close()
