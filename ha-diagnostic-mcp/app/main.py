"""Remote, read-only Home Assistant diagnostic MCP server."""

from __future__ import annotations

import hmac
import logging
import os
import re
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from app.config import Settings
from app.providers.config_files import ConfigFiles
from app.providers.homeassistant_api import HomeAssistantAPI
from app.providers.websocket import HomeAssistantWebSocket
from app.security import SecurityError, bounded, redact, validate_entity_id

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
LOGGER = logging.getLogger(__name__)
ENTITY_REFERENCE = re.compile(r"\b[a-z_][a-z0-9_]*\.[a-z0-9_]+\b")


class BearerAndOriginMiddleware(BaseHTTPMiddleware):
    """Protect MCP from unauthenticated use and browser DNS-rebinding attacks."""

    def __init__(self, app: Any, token: str) -> None:
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if request.url.path == "/healthz":
            return await call_next(request)
        # Remote MCP clients do not require browser origins. Rejecting every Origin is
        # stricter than reflecting Host and prevents DNS-rebinding via an attacker host.
        if request.headers.get("origin"):
            return JSONResponse({"error": "Origin not allowed"}, status_code=403)
        supplied = request.headers.get("authorization", "")
        expected = f"Bearer {self._token}"
        if not hmac.compare_digest(supplied, expected):
            return JSONResponse(
                {"error": "Authentication required"}, status_code=401, headers={"WWW-Authenticate": "Bearer"}
            )
        return await call_next(request)


def create_mcp(settings: Settings, api: HomeAssistantAPI, ws: HomeAssistantWebSocket, files: ConfigFiles) -> FastMCP:
    # Explicit non-loopback bind avoids FastMCP's localhost-only Host allowlist.
    # Browser-origin requests are rejected by the outer middleware instead.
    mcp = FastMCP("Home Assistant Diagnostic MCP", host="0.0.0.0")

    def output(value: Any) -> dict[str, Any]:
        return bounded(value, settings.max_response_bytes)

    async def registries() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        entities, devices = await __import__("asyncio").gather(
            ws.command({"type": "config/entity_registry/list"}),
            ws.command({"type": "config/device_registry/list"}),
        )
        return entities, devices

    async def entity_context(entity_id: str) -> dict[str, Any]:
        entity_id = validate_entity_id(entity_id)
        entity_entries, devices = await registries()
        entry = next((item for item in entity_entries if item.get("entity_id") == entity_id), None)
        device = next((item for item in devices if entry and item.get("id") == entry.get("device_id")), None)
        config_entry = None
        if entry and entry.get("config_entry_id"):
            try:
                config_entry = await ws.command(
                    {"type": "config/config_entries/get", "entry_id": entry["config_entry_id"]}
                )
            except Exception:
                config_entry = {"entry_id": entry["config_entry_id"], "available": False}
        return redact({"entity_registry": entry, "device": device, "config_entry": config_entry})

    @mcp.tool()
    async def search_entities(query: str) -> dict[str, Any]:
        """Search current entity IDs and friendly names. Query is limited to 100 characters."""
        if not query or len(query) > 100:
            raise SecurityError("query must contain 1 to 100 characters")
        needle = query.casefold()
        states = await api.states()
        results = [
            {
                "entity_id": item["entity_id"],
                "friendly_name": item.get("attributes", {}).get("friendly_name"),
                "state": item.get("state"),
            }
            for item in states
            if needle in item["entity_id"].casefold()
            or needle in str(item.get("attributes", {}).get("friendly_name", "")).casefold()
        ]
        return output(results[:50])

    @mcp.tool()
    async def get_entity_state(entity_id: str) -> dict[str, Any]:
        """Return one entity's current state, sanitized attributes, and timestamps."""
        return output(await api.state(validate_entity_id(entity_id)))

    @mcp.tool()
    async def list_unavailable_entities() -> dict[str, Any]:
        """List current unknown or unavailable entities with registry relationship metadata."""
        states = await api.states()
        entity_entries, devices = await registries()
        by_entity = {item.get("entity_id"): item for item in entity_entries}
        by_device = {item.get("id"): item for item in devices}
        result = []
        for state in states:
            if state.get("state") not in {"unavailable", "unknown"}:
                continue
            entry = by_entity.get(state["entity_id"], {})
            device = by_device.get(entry.get("device_id"), {})
            result.append(
                {
                    "entity_id": state["entity_id"],
                    "friendly_name": state.get("attributes", {}).get("friendly_name"),
                    "state": state["state"],
                    "platform": entry.get("platform"),
                    "device": device.get("name_by_user") or device.get("name"),
                    "last_changed": state.get("last_changed"),
                    "last_updated": state.get("last_updated"),
                }
            )
        return output(result[: settings.max_records])

    @mcp.tool()
    async def get_entity_history(entity_id: str, hours: int = 24) -> dict[str, Any]:
        """Return bounded chronological state history (1-168 hours, maximum 200 records)."""
        entity_id = validate_entity_id(entity_id)
        if not 1 <= hours <= settings.max_hours:
            raise SecurityError(f"hours must be between 1 and {settings.max_hours}")
        return output((await api.history(entity_id, hours))[-settings.max_records :])

    @mcp.tool()
    async def get_entity_registry_entry(entity_id: str) -> dict[str, Any]:
        """Return registry metadata and its device/config-entry relationship."""
        return output(await entity_context(entity_id))

    @mcp.tool()
    async def get_device_info(identifier: str) -> dict[str, Any]:
        """Look up a device by entity ID or exact device registry ID."""
        if "." in identifier:
            return output(await entity_context(identifier))
        _, devices = await registries()
        device = next((item for item in devices if item.get("id") == identifier), None)
        if not device:
            raise SecurityError("Device not found")
        return output(device)

    @mcp.tool()
    async def get_config_entry(identifier: str) -> dict[str, Any]:
        """Return config-entry metadata by entity ID or config-entry ID."""
        entry_id = (
            (await entity_context(identifier)).get("entity_registry", {}).get("config_entry_id")
            if "." in identifier
            else identifier
        )
        if not entry_id:
            raise SecurityError("No config entry is associated with identifier")
        return output(await ws.command({"type": "config/config_entries/get", "entry_id": entry_id}))

    @mcp.tool()
    async def diagnose_entity(entity_id: str, hours: int = 24) -> dict[str, Any]:
        """Aggregate deterministic entity evidence; it does not infer a root cause."""
        entity_id = validate_entity_id(entity_id)
        if not 1 <= hours <= settings.max_hours:
            raise SecurityError("hours outside allowed range")
        state, context, history, events, unavailable = await __import__("asyncio").gather(
            api.state(entity_id),
            entity_context(entity_id),
            api.history(entity_id, hours),
            api.logbook(entity_id, hours),
            list_unavailable_entities(),
        )
        entry = context.get("entity_registry") or {}
        unavailable_data = unavailable["data"]
        related_device = [
            item
            for item in unavailable_data
            if entry.get("device_id") and item.get("device") == (context.get("device") or {}).get("name_by_user")
        ]
        related_platform = [
            item for item in unavailable_data if entry.get("platform") and item.get("platform") == entry.get("platform")
        ]
        return output(
            {
                "current_state": state,
                "registry": context,
                "recent_history": history[-settings.max_records :],
                "recent_logbook": events[-settings.max_records :],
                "unavailable_same_device": related_device,
                "unavailable_same_integration": related_platform,
            }
        )

    def automation_config(entity_id: str) -> dict[str, Any]:
        validate_entity_id(entity_id)
        if not entity_id.startswith("automation."):
            raise SecurityError("Expected an automation entity_id")
        automations = files.read_yaml("automations.yaml") or []
        if not isinstance(automations, list):
            raise SecurityError("automations.yaml is not a list")
        wanted = entity_id.split(".", 1)[1]
        for item in automations:
            if isinstance(item, dict) and (
                str(item.get("id", "")) == wanted or str(item.get("alias", "")).lower().replace(" ", "_") == wanted
            ):
                return redact(item)
        raise SecurityError("Automation YAML was not found; UI-managed automation configuration is unavailable")

    async def trace_item_id(entity_id: str) -> str:
        state = await api.state(entity_id)
        return str(state.get("attributes", {}).get("id") or entity_id.split(".", 1)[1])

    @mcp.tool()
    async def get_automation_config(automation_entity_id: str) -> dict[str, Any]:
        """Return sanitized YAML automation configuration where YAML-managed."""
        return output(automation_config(automation_entity_id))

    @mcp.tool()
    async def list_automation_traces(automation_entity_id: str) -> dict[str, Any]:
        """List trace summaries using Core's admin-gated trace/list WebSocket command."""
        validate_entity_id(automation_entity_id)
        return output(
            await ws.command(
                {"type": "trace/list", "domain": "automation", "item_id": await trace_item_id(automation_entity_id)}
            )
        )

    @mcp.tool()
    async def get_automation_trace(automation_entity_id: str, run_id: str) -> dict[str, Any]:
        """Return a bounded, sanitized raw trace with trigger, path, result, and error evidence."""
        validate_entity_id(automation_entity_id)
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", run_id):
            raise SecurityError("Invalid run_id")
        trace = await ws.command(
            {
                "type": "trace/get",
                "domain": "automation",
                "item_id": await trace_item_id(automation_entity_id),
                "run_id": run_id,
            }
        )
        return output(trace)

    @mcp.tool()
    async def diagnose_automation(automation_entity_id: str, hours: int = 24) -> dict[str, Any]:
        """Aggregate configuration, traces, referenced entity states/history, and logbook evidence."""
        config = automation_config(automation_entity_id)
        references = sorted(set(ENTITY_REFERENCE.findall(str(config))))[:30]
        states = await __import__("asyncio").gather(*(api.state(ref) for ref in references), return_exceptions=True)
        histories = await __import__("asyncio").gather(
            *(api.history(ref, min(hours, settings.max_hours)) for ref in references[:10]), return_exceptions=True
        )
        traces = await list_automation_traces(automation_entity_id)
        return output(
            {
                "configuration": config,
                "recent_traces": traces["data"],
                "referenced_entities": [
                    {
                        "entity_id": ref,
                        "current_state": value if not isinstance(value, Exception) else {"available": False},
                    }
                    for ref, value in zip(references, states, strict=True)
                ],
                "recent_referenced_history": {
                    ref: value[-settings.max_records :]
                    for ref, value in zip(references[:10], histories, strict=True)
                    if not isinstance(value, Exception)
                },
            }
        )

    @mcp.tool()
    async def get_core_configuration() -> dict[str, Any]:
        """Return sanitized configuration.yaml only; secrets and arbitrary includes are never exposed."""
        return output(files.read_yaml("configuration.yaml"))

    @mcp.tool()
    async def get_automation_yaml(automation_entity_id: str) -> dict[str, Any]:
        """Return one sanitized YAML-managed automation."""
        return output(automation_config(automation_entity_id))

    @mcp.tool()
    async def get_script_yaml(script_id: str) -> dict[str, Any]:
        """Return a named sanitized YAML script by its script entity ID suffix."""
        validate_entity_id(script_id)
        if not script_id.startswith("script."):
            raise SecurityError("Expected a script entity_id")
        scripts = files.read_yaml("scripts.yaml") or {}
        item = scripts.get(script_id.split(".", 1)[1]) if isinstance(scripts, dict) else None
        if item is None:
            raise SecurityError("Script YAML was not found")
        return output(item)

    @mcp.tool()
    async def get_scene_yaml(scene_id: str) -> dict[str, Any]:
        """Return a named sanitized YAML scene by ID or entity ID suffix."""
        wanted = scene_id.split(".", 1)[1] if scene_id.startswith("scene.") else scene_id
        scenes = files.read_yaml("scenes.yaml") or []
        item = next((item for item in scenes if isinstance(item, dict) and str(item.get("id", "")) == wanted), None)
        if item is None:
            raise SecurityError("Scene YAML was not found")
        return output(item)

    @mcp.tool()
    async def search_configuration(query: str) -> dict[str, Any]:
        """Search only approved YAML sources; neither paths nor glob patterns are accepted."""
        if not settings.allow_config_search:
            raise SecurityError("Configuration search is disabled")
        if not query or len(query) > 100:
            raise SecurityError("query must contain 1 to 100 characters")
        matches = []
        for path in files.approved_paths():
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if query.casefold() in line.casefold():
                    matches.append(
                        {"source_file": str(path.relative_to(settings.config_root)), "line": number, "content": line}
                    )
                    if len(matches) >= settings.max_search_matches:
                        return output(matches)
        return output(matches)

    @mcp.tool()
    async def get_homeassistant_logs(lines: int = 100) -> dict[str, Any]:
        """Return bounded Core error-log lines through its supported read-only REST endpoint."""
        if not 1 <= lines <= settings.max_log_lines:
            raise SecurityError("lines outside allowed range")
        try:
            return output((await api.error_log()).splitlines()[-lines:])
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 404:
                return output({"available": False, "reason": "Core error-log endpoint is unavailable on this instance"})
            raise

    @mcp.tool()
    async def search_homeassistant_logs(query: str, lines: int = 100) -> dict[str, Any]:
        """Search bounded Core error logs without host or journal access."""
        if not query or len(query) > 100 or not 1 <= lines <= settings.max_log_lines:
            raise SecurityError("Invalid query or lines")
        try:
            result = [line for line in (await api.error_log()).splitlines() if query.casefold() in line.casefold()]
            return output(result[-lines:])
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 404:
                return output({"available": False, "reason": "Core error-log endpoint is unavailable on this instance"})
            raise

    @mcp.tool()
    async def get_ha_system_info() -> dict[str, Any]:
        """Return safe Core version, timezone, unit settings, and loaded components."""
        config, components = await __import__("asyncio").gather(api.config(), api.components())
        allowed = {key: config.get(key) for key in ("version", "time_zone", "unit_system")}
        allowed["components"] = components
        return output(allowed)

    return mcp


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or Settings.load()
    api = HomeAssistantAPI(os.environ.get("SUPERVISOR_TOKEN", ""))
    mcp = create_mcp(settings, api, HomeAssistantWebSocket(), ConfigFiles(settings.config_root))
    # FastMCP owns the exact /mcp route; mounting it would turn the public route into /mcp/.
    app = mcp.streamable_http_app()
    app.router.routes.append(Route("/healthz", lambda request: JSONResponse({"status": "ok"})))
    app.add_middleware(BearerAndOriginMiddleware, token=settings.auth_token)
    return app


if __name__ == "__main__":
    config = Settings.load()
    uvicorn.run(create_app(config), host="0.0.0.0", port=8765, log_level=config.log_level)
