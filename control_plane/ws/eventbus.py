"""
control_plane/ws/eventbus.py — In-Process Pub/Sub Dispatch Loop (Req 14.1, 14.4)
Continuous asyncio dispatch loop decoupled from pipeline workers.
"""
from __future__ import annotations

import asyncio
from control_plane.ws.manager import manager as ws_manager


class EventBus:
    """Asyncio Queue pub/sub bus (Req 14.4)."""

    def __init__(self, maxsize: int = 10_000) -> None:
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._dispatch_task: asyncio.Task | None = None

    def start(self) -> None:
        """Start continuous background dispatch task (Req 14.4)."""
        loop = asyncio.get_event_loop()
        self._dispatch_task = loop.create_task(self._dispatch_loop())

    async def publish(self, entry: dict) -> None:
        """Publish event without blocking caller (put_nowait, Req 14.1)."""
        try:
            self.queue.put_nowait(entry)
        except asyncio.QueueFull:
            pass  # bound queue capacity

    async def _dispatch_loop(self) -> None:
        """Continuous dispatch loop reading queue and triggering WebSocket broadcast."""
        while True:
            entry = await self.queue.get()
            try:
                await ws_manager.broadcast(entry)
            except Exception:
                pass
            finally:
                self.queue.task_done()

    def stop(self) -> None:
        if self._dispatch_task:
            self._dispatch_task.cancel()
