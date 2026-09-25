"""
sdk/background.py — Event-Driven Background Core (Req 8.1, 8.4)
Detects file changes in real-time using OS-level watchdog events and enqueues them into ScanQueue.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from sdk.pre_filter import pre_filter


class PantheonEventHandler(FileSystemEventHandler):
    """Bridge watchdog thread → asyncio ScanQueue."""

    def __init__(
        self,
        scan_queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
        asset_owner_role: str = "UNKNOWN",
    ) -> None:
        super().__init__()
        self._queue = scan_queue
        self._loop = loop
        self._asset_owner_role = asset_owner_role

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        result = pre_filter(event.src_path, asset_owner_role=self._asset_owner_role)
        if result.passed:
            asyncio.run_coroutine_threadsafe(
                self._enqueue(event.src_path, result.chunks),
                self._loop,
            )

    async def _enqueue(self, path: str, chunks: list) -> None:
        if self._queue.full():
            # Discard oldest to make room — bounded queue contract (Req 8.3)
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        await self._queue.put({"path": path, "chunks": chunks})


class BackgroundScanner:
    """Manages the watchdog Observer and async worker pool (Req 8.1, 8.4)."""

    def __init__(
        self,
        watch_path: str,
        worker_count: int = 3,
        queue_maxsize: int = 1_000,
        asset_owner_role: str = "UNKNOWN",
    ) -> None:
        self._watch_path = watch_path
        self._worker_count = worker_count
        self._loop = asyncio.get_event_loop()
        self.scan_queue: asyncio.Queue = asyncio.Queue(maxsize=queue_maxsize)
        self._observer = Observer()
        self._handler = PantheonEventHandler(self.scan_queue, self._loop, asset_owner_role=asset_owner_role)

    def start(self) -> None:
        self._observer.schedule(self._handler, self._watch_path, recursive=True)
        self._observer.start()
        for _ in range(self._worker_count):
            self._loop.create_task(self._worker())

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join()

    async def _worker(self) -> None:
        """Consume ScanQueue events one at a time."""
        while True:
            event = await self.scan_queue.get()
            try:
                await self._process(event)
            finally:
                self.scan_queue.task_done()

    async def _process(self, event: dict) -> None:
        # Pipeline worker ingestion: ForensicExtractor → HTTP POST
        pass
