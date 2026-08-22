import httpx
import pytest

from app.providers.homeassistant_api import HomeAssistantAPI


class FailingReadClient:
    async def get(self, *args, **kwargs):
        request = httpx.Request("GET", "http://supervisor/core/api/states")
        response = httpx.Response(503, request=request)
        raise httpx.HTTPStatusError("Server error", request=request, response=response)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_home_assistant_api_errors_propagate_without_write_attempt():
    api = HomeAssistantAPI("supervisor-token-not-to-log")
    api._client = FailingReadClient()
    with pytest.raises(httpx.HTTPStatusError):
        await api.states()


def test_provider_has_no_mutating_http_methods():
    assert not hasattr(HomeAssistantAPI, "post")
    assert not hasattr(HomeAssistantAPI, "put")
    assert not hasattr(HomeAssistantAPI, "delete")
