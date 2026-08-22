"""A fixed allowlist of read-only WebSocket commands, including trace retrieval."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import websockets

READ_ONLY_COMMANDS = {
    "trace/list",
    "trace/get",
    "config/entity_registry/list",
    "config/device_registry/list",
    "config/config_entries/get",
}


class HomeAssistantWebSocket:
    async def command(self, command: dict[str, Any]) -> Any:
        if command.get("type") not in READ_ONLY_COMMANDS:
            raise ValueError("WebSocket command is not allowlisted")
        token = os.environ.get("SUPERVISOR_TOKEN")
        if not token:
            raise RuntimeError("SUPERVISOR_TOKEN is unavailable")
        async with websockets.connect("ws://supervisor/core/websocket", open_timeout=10) as ws:
            required = json.loads(await ws.recv())
            if required.get("type") != "auth_required":
                raise RuntimeError("Unexpected Home Assistant WebSocket handshake")
            await ws.send(json.dumps({"type": "auth", "access_token": token}))
            auth = json.loads(await ws.recv())
            if auth.get("type") != "auth_ok":
                raise RuntimeError("Home Assistant WebSocket authentication failed")
            message = {"id": 1, **command}
            await ws.send(json.dumps(message))
            while True:
                result = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
                if result.get("id") == 1 and result.get("type") == "result":
                    if not result.get("success"):
                        raise RuntimeError(result.get("error", {}).get("message", "Home Assistant WebSocket error"))
                    return result.get("result")
