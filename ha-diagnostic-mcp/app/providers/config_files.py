"""Purpose-built configuration reader; it has no directory or arbitrary-path API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.security import SecurityError, safe_config_path


class SecretSafeLoader(yaml.SafeLoader):
    pass


def _secret(loader: SecretSafeLoader, node: yaml.Node) -> str:
    return "<REDACTED>"


SecretSafeLoader.add_constructor("!secret", _secret)


class ConfigFiles:
    def __init__(self, root: Path) -> None:
        self.root = root

    def read_yaml(self, relative_path: str) -> Any:
        path = safe_config_path(self.root, relative_path)
        return self._load(path, set())

    def _load(self, path: Path, visited: set[Path]) -> Any:
        """Resolve !include only when it remains a non-secret YAML file under the mount."""
        if path in visited:
            raise SecurityError("Recursive YAML include is not allowed")
        visited.add(path)
        root = self.root.resolve()

        class IncludeLoader(SecretSafeLoader):
            pass

        def include(loader: IncludeLoader, node: yaml.Node) -> Any:
            target = (path.parent / loader.construct_scalar(node)).resolve()
            try:
                relative = target.relative_to(root)
            except ValueError as err:
                raise SecurityError("YAML include escapes configuration root") from err
            if target.suffix not in {".yaml", ".yml"} or target.name == "secrets.yaml" or ".storage" in relative.parts:
                raise SecurityError("YAML include is not approved")
            return self._load(target, visited)

        IncludeLoader.add_constructor("!include", include)
        try:
            return yaml.load(path.read_text(encoding="utf-8"), Loader=IncludeLoader)
        finally:
            visited.remove(path)

    def approved_paths(self) -> list[Path]:
        paths = [
            self.root / name
            for name in ("configuration.yaml", "automations.yaml", "scripts.yaml", "scenes.yaml", "groups.yaml")
        ]
        packages = self.root / "packages"
        if packages.is_dir():
            paths.extend(packages.rglob("*.yaml"))
            paths.extend(packages.rglob("*.yml"))
        return [safe_config_path(self.root, str(path.relative_to(self.root))) for path in paths if path.is_file()]
