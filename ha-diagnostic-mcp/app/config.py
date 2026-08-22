"""Add-on options and intentionally conservative response limits."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    auth_token: str
    log_level: str
    allow_config_search: bool
    allow_storage_metadata: bool
    config_root: Path = Path("/homeassistant")
    max_hours: int = 168
    max_records: int = 200
    max_log_lines: int = 200
    max_search_matches: int = 30
    max_response_bytes: int = 100_000

    @classmethod
    def load(cls) -> Settings:
        options_path = Path("/data/options.json")
        options = json.loads(options_path.read_text()) if options_path.exists() else {}
        token = str(options.get("mcp_auth_token", ""))
        if len(token) < 32:
            raise RuntimeError("mcp_auth_token must contain at least 32 characters")
        return cls(
            auth_token=token,
            log_level=str(options.get("log_level", "info")),
            allow_config_search=bool(options.get("allow_config_search", True)),
            allow_storage_metadata=bool(options.get("allow_storage_metadata", False)),
            config_root=Path(os.environ.get("HA_CONFIG_DIR", "/homeassistant")),
        )
