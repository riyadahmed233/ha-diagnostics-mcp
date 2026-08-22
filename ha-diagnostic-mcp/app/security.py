"""Validation, redaction, filesystem confinement, and response bounding."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from starlette.responses import JSONResponse

SENSITIVE_KEY = re.compile(
    r"password|passwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|authorization|bearer|credential",
    re.I,
)
SENSITIVE_TEXT = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|authorization|credential)\s*[:=]\s*([^\s,}\]]+)"
)
ENTITY_ID = re.compile(r"^[a-z_][a-z0-9_]*\.[a-z0-9_]+$")
DENIED_NAMES = {"secrets.yaml", ".storage/auth", ".storage/onboarding", ".storage/http", ".storage/core.restore_state"}
ROOT_FILES = {"configuration.yaml", "automations.yaml", "scripts.yaml", "scenes.yaml", "groups.yaml"}


class SecurityError(ValueError):
    """Safe error for rejected external input."""


def validate_entity_id(entity_id: str) -> str:
    if not ENTITY_ID.fullmatch(entity_id):
        raise SecurityError("Invalid entity_id")
    return entity_id


def redact(value: Any, key: str | None = None) -> Any:
    if key and SENSITIVE_KEY.search(key):
        return "<REDACTED>"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        if value.startswith("!secret") or "!secret " in value:
            return "<REDACTED>"
        return SENSITIVE_TEXT.sub(lambda match: f"{match.group(1)}: <REDACTED>", value)
    return value


def safe_config_path(root: Path, requested: str) -> Path:
    """Return only an approved canonical YAML path below the read-only mount."""
    if "\x00" in requested:
        raise SecurityError("Invalid configuration path")
    root = root.resolve()
    candidate = (root / requested).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as err:
        raise SecurityError("Configuration path escapes allowed root") from err
    name = relative.as_posix()
    if name in DENIED_NAMES or name.startswith(".storage/"):
        raise SecurityError("Configuration file is not allowed")
    if candidate.suffix not in {".yaml", ".yml"}:
        raise SecurityError("Only approved YAML configuration is allowed")
    if name not in ROOT_FILES and not name.startswith("packages/"):
        raise SecurityError("Configuration file is not allowlisted")
    return candidate


def bounded(value: Any, max_bytes: int) -> dict[str, Any]:
    """Preserve valid JSON and disclose truncation instead of silently overflowing context."""
    value = redact(value)
    encoded = json.dumps(value, default=str, separators=(",", ":"))
    if len(encoded.encode()) <= max_bytes:
        return {"data": value, "truncated": False}
    if isinstance(value, list):
        kept: list[Any] = []
        for item in value:
            if len(json.dumps(kept + [item], default=str).encode()) > max_bytes - 200:
                break
            kept.append(item)
        return {"data": kept, "truncated": True, "message": "Response truncated; use a narrower query."}
    return {"data": "<TRUNCATED>", "truncated": True, "message": "Response exceeded limit; use a narrower query."}


def safe_error(error: Exception) -> JSONResponse:
    return JSONResponse(
        {"error": "Home Assistant diagnostic request failed", "detail": str(error)[:300]}, status_code=502
    )
