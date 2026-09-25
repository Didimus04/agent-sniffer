"""
control_plane/ws/manager.py — WebSocket Connection Manager (Req 14.8–14.11)
Maintains per-role WebSocket registries; broadcasts data-masked payloads to ADMIN clients.
"""
from __future__ import annotations

import json
import re
from fastapi import WebSocket, WebSocketDisconnect

from control_plane.ws.routing import ws_targets

# Data Masking Patterns for ADMIN connections (Req 13.4, 14.10)
_MASKING_PATTERNS = [
    (r'(?i)(password|secret|api_key|token)\s*=\s*["\']?[^"\'\s]+["\']?', r'\1=[REDACTED:CREDENTIAL]'),
    (r'\b[A-Za-z0-9+/]{32,}={0,2}\b', '[REDACTED:BASE64]'),
    (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '[REDACTED:CARD]'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[REDACTED:EMAIL]'),
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED:SSN]'),
]


def mask_payload_for_admin(text: str) -> str:
    """Mask sensitive patterns for ADMIN connections (Req 13.4, 14.10)."""
    res = text
    for pat, repl in _MASKING_PATTERNS:
        res = re.sub(pat, repl, res)
    return res


class WebSocketManager:
    """Per-role WebSocket connection registry and push router (Req 14.9–14.10)."""

    def __init__(self) -> None:
        self.registries: dict[str, set[WebSocket]] = {
            "SUPER_ADMIN": set(),
            "ADMIN": set(),
        }

    async def connect(self, websocket: WebSocket, role: str) -> None:
        """Register validated connection under role (Req 14.9)."""
        await websocket.accept()
        if role in self.registries:
            self.registries[role].add(websocket)

    def disconnect(self, websocket: WebSocket, role: str | None = None) -> None:
        """Silently remove dropped connection (Req 14.9)."""
        if role and role in self.registries:
            self.registries[role].discard(websocket)
        else:
            for s in self.registries.values():
                s.discard(websocket)

    async def broadcast(self, entry: dict) -> None:
        """Broadcast event to allowed roles per routing rules (Req 14.5–14.7, Prop 20)."""
        targets = ws_targets(entry)
        if not targets:
            return

        # Prepare payloads
        super_admin_payload = json.dumps(entry)

        admin_entry = dict(entry)
        if "masked_payload" in admin_entry and admin_entry["masked_payload"]:
            admin_entry["masked_payload"] = mask_payload_for_admin(admin_entry["masked_payload"])
        admin_entry["masked_for_admin"] = True
        admin_payload = json.dumps(admin_entry)

        # Broadcast to SUPER_ADMIN connections
        if "SUPER_ADMIN" in targets:
            dead = set()
            for ws in list(self.registries["SUPER_ADMIN"]):
                try:
                    await ws.send_text(super_admin_payload)
                except (WebSocketDisconnect, Exception):
                    dead.add(ws)
            for ws in dead:
                self.disconnect(ws, "SUPER_ADMIN")

        # Broadcast to ADMIN connections (masked payload, CEO events excluded by ws_targets)
        if "ADMIN" in targets:
            dead = set()
            for ws in list(self.registries["ADMIN"]):
                try:
                    await ws.send_text(admin_payload)
                except (WebSocketDisconnect, Exception):
                    dead.add(ws)
            for ws in dead:
                self.disconnect(ws, "ADMIN")


# Global singleton manager
manager = WebSocketManager()
