"""Tests for app.osint.breach."""

import pytest

from app.osint.breach import BreachCheckResult, check_password_breach


class FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class FakeClient:
    def __init__(self, response=None, side_effect=None):
        self._response = response
        self._side_effect = side_effect

    async def get(self, url, **kwargs):
        if self._side_effect:
            raise self._side_effect
        return self._response


@pytest.mark.asyncio
async def test_breached_password():
    # SHA-1 of "password123" = CBFDA C6008F9CAB4083784CBD1874F76618D2A97
    fake = FakeClient(FakeResponse(200, "C6008F9CAB4083784CBD1874F76618D2A97:3\n"))
    result = await check_password_breach(fake, "password123")
    assert result.breached is True
    assert result.count == 3
    assert result.error is False


@pytest.mark.asyncio
async def test_safe_password():
    fake = FakeClient(FakeResponse(200, "AAAAAA:0\n"))
    result = await check_password_breach(fake, "xK9!mZ2@qW7")
    assert result.breached is False
    assert result.count == 0


@pytest.mark.asyncio
async def test_non_200_returns_error():
    fake = FakeClient(FakeResponse(429))
    result = await check_password_breach(fake, "test")
    assert result.error is True
    assert result.breached is False


@pytest.mark.asyncio
async def test_network_error_returns_error():
    from curl_cffi.requests.errors import RequestsError
    fake = FakeClient(side_effect=RequestsError("timeout"))
    result = await check_password_breach(fake, "test")
    assert result.error is True
    assert result.breached is False
