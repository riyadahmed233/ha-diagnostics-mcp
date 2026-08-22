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

        def validate_target(target: Path, directory: bool = False) -> Path:
            target = target.resolve()
            try:
                relative = target.relative_to(root)
            except ValueError as err:
                raise SecurityError("YAML include escapes configuration root") from err
            valid_type = target.is_dir() if directory else target.suffix in {".yaml", ".yml"}
            if not valid_type or target.name == "secrets.yaml" or ".storage" in relative.parts:
                raise SecurityError("YAML include is not approved")
            return target

        def include_target(loader: IncludeLoader, node: yaml.Node, directory: bool = False) -> Path:
            return validate_target(path.parent / loader.construct_scalar(node), directory)

        def include(loader: IncludeLoader, node: yaml.Node) -> Any:
            target = include_target(loader, node)
            return self._load(target, visited)

        def directory_values(loader: IncludeLoader, node: yaml.Node) -> list[tuple[Path, Any]]:
            directory = include_target(loader, node, directory=True)
            values = []
            for candidate in sorted((*directory.glob("*.yaml"), *directory.glob("*.yml"))):
                # Resolve every child to prevent a symlink inside an approved directory escaping it.
                resolved = validate_target(candidate)
                values.append((resolved, self._load(resolved, visited)))
            return values

        def include_dir_list(loader: IncludeLoader, node: yaml.Node) -> list[Any]:
            return [value for _, value in directory_values(loader, node)]

        def include_dir_named(loader: IncludeLoader, node: yaml.Node) -> dict[str, Any]:
            return {candidate.stem: value for candidate, value in directory_values(loader, node)}

        def include_dir_merge_named(loader: IncludeLoader, node: yaml.Node) -> dict[str, Any]:
            merged: dict[str, Any] = {}
            for _, value in directory_values(loader, node):
                if not isinstance(value, dict):
                    raise SecurityError("!include_dir_merge_named files must contain mappings")
                merged.update(value)
            return merged

        def include_dir_merge_list(loader: IncludeLoader, node: yaml.Node) -> list[Any]:
            merged: list[Any] = []
            for _, value in directory_values(loader, node):
                if not isinstance(value, list):
                    raise SecurityError("!include_dir_merge_list files must contain lists")
                merged.extend(value)
            return merged

        IncludeLoader.add_constructor("!include", include)
        IncludeLoader.add_constructor("!include_dir_list", include_dir_list)
        IncludeLoader.add_constructor("!include_dir_named", include_dir_named)
        IncludeLoader.add_constructor("!include_dir_merge_named", include_dir_merge_named)
        IncludeLoader.add_constructor("!include_dir_merge_list", include_dir_merge_list)
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
