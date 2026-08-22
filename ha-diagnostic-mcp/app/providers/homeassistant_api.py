"""Read-only REST client. This class deliberately has no POST/PUT/DELETE method."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


class HomeAssistantAPI:
    def __init__(self, token: str) -> None:
        self._headers = {"Authorization": f"Bearer {token}"}
        self._client = httpx.AsyncClient(base_url="http://supervisor/core/api/", headers=self._headers, timeout=15)

    async def get(self, path: str, params: dict[str, str] | None = None) -> Any:
        response = await self._client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    async def states(self) -> list[dict[str, Any]]:
        return await self.get("states")

    async def state(self, entity_id: str) -> dict[str, Any]:
        return await self.get(f"states/{entity_id}")

    async def history(self, entity_id: str, hours: int) -> list[dict[str, Any]]:
        start = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
        result = await self.get(
            f"history/period/{start}", {"filter_entity_id": entity_id, "minimal_response": "", "no_attributes": ""}
        )
        return result[0] if result else []

    async def logbook(self, entity_id: str, hours: int) -> list[dict[str, Any]]:
        start = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
        return await self.get(f"logbook/{start}", {"entity": entity_id})

    async def config(self) -> dict[str, Any]:
        return await self.get("config")

    async def components(self) -> list[str]:
        return await self.get("components")

    async def error_log(self) -> str:
        response = await self._client.get("error_log")
        response.raise_for_status()
        return response.text

    async def close(self) -> None:
        await self._client.aclose()
