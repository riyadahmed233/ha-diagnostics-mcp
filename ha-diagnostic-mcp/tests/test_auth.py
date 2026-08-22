from starlette.testclient import TestClient

from app.config import Settings
from app.main import create_app


def settings() -> Settings:
    return Settings(auth_token="a" * 32, log_level="warning", allow_config_search=True, allow_storage_metadata=False)


def test_health_is_unauthenticated():
    with TestClient(create_app(settings())) as client:
        assert client.get("/healthz").json() == {"status": "ok"}


def test_mcp_requires_bearer_authentication():
    with TestClient(create_app(settings())) as client:
        assert client.post("/mcp", json={}).status_code == 401
        response = client.post("/mcp", headers={"Authorization": "Bearer " + "a" * 32}, json={})
        assert response.status_code != 401
        assert not response.is_redirect


def test_cross_origin_is_rejected():
    with TestClient(create_app(settings())) as client:
        response = client.post(
            "/mcp", headers={"Authorization": "Bearer " + "a" * 32, "Origin": "https://evil.example"}, json={}
        )
        assert response.status_code == 403
