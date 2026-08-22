from pathlib import Path

import pytest

from app.providers.config_files import ConfigFiles
from app.security import SecurityError, bounded, redact, safe_config_path, validate_entity_id


def test_redacts_sensitive_values_and_secret_references():
    value = {"password": "not-for-models", "nested": {"api_key": "also-not-for-models"}, "ref": "!secret mqtt_password"}
    assert redact(value) == {"password": "<REDACTED>", "nested": {"api_key": "<REDACTED>"}, "ref": "<REDACTED>"}


@pytest.mark.parametrize(
    "path",
    [
        "secrets.yaml",
        ".storage/auth",
        "../../secrets.yaml",
        "packages/../../secrets.yaml",
        ".storage/core.restore_state",
    ],
)
def test_sensitive_and_escape_paths_are_rejected(tmp_path: Path, path: str):
    with pytest.raises(SecurityError):
        safe_config_path(tmp_path, path)


def test_approved_yaml_can_be_resolved(tmp_path: Path):
    path = tmp_path / "packages" / "lights.yaml"
    path.parent.mkdir()
    path.write_text("light: {}")
    assert safe_config_path(tmp_path, "packages/lights.yaml") == path


@pytest.mark.parametrize("entity_id", ["light.kitchen", "binary_sensor.door_2"])
def test_valid_entity_ids(entity_id: str):
    assert validate_entity_id(entity_id) == entity_id


@pytest.mark.parametrize("entity_id", ["light", "light/kitchen", "light.kitchen;rm", "../../secrets.yaml"])
def test_malformed_entity_ids_are_rejected(entity_id: str):
    with pytest.raises(SecurityError):
        validate_entity_id(entity_id)


def test_response_limit_is_disclosed():
    result = bounded([{"value": "x" * 1000}] * 20, 200)
    assert result["truncated"] is True
    assert "narrower" in result["message"]


def test_textual_key_value_secrets_are_redacted():
    assert redact("mqtt password: exposed-value") == "mqtt password: <REDACTED>"


def test_safe_yaml_include_is_resolved(tmp_path: Path):
    (tmp_path / "configuration.yaml").write_text("automation: !include automations.yaml")
    (tmp_path / "automations.yaml").write_text("- id: safe")
    assert ConfigFiles(tmp_path).read_yaml("configuration.yaml") == {"automation": [{"id": "safe"}]}


def test_secret_yaml_include_is_rejected(tmp_path: Path):
    (tmp_path / "configuration.yaml").write_text("mqtt: !include secrets.yaml")
    (tmp_path / "secrets.yaml").write_text("password: no")
    with pytest.raises(SecurityError):
        ConfigFiles(tmp_path).read_yaml("configuration.yaml")
