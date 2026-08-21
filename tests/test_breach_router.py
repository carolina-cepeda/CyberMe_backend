"""Tests for app.routers.breach (breach, score, verify endpoints)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from starlette.requests import Request

from app.db.database import (
    create_scan,
    finish_scan,
    get_or_create_user,
    save_scan_result,
    save_score,
)


def _starlette_request():
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    return Request(scope)


def _make_fake_result(platform_name="GitHub", is_core=True, detected=True):
    target = MagicMock()
    target.platform_name = platform_name
    target.exists_status_code = 200
    target.exists_marker = '"login"'
    target.miss_marker = ""
    target.category = "coding"
    target.is_core = is_core
    target.protection = ()
    target.probe_url_template = f"https://{platform_name.lower()}.com/{{account}}"
    target.request_headers = {}

    result = MagicMock()
    result.target = target
    result.requested_url = f"https://{platform_name.lower()}.com/testuser"
    result.observed_status_code = 200
    result.verdict.value = "detected" if detected else "not_found"
    result.detected = detected
    result.blocked = False
    result.inconclusive = False
    result.verdict_reason = None
    result.exists_marker_matched = True
    result.miss_marker_matched = False
    return result


# --- /api/breach ---


@pytest.mark.asyncio
@patch("app.routers.breach.check_password_breach")
async def test_breach_check_breached(mock_check):
    from app.routers.breach import breach_check, BreachCheckRequest

    mock_check.return_value = MagicMock(
        breached=True, count=5, prefix="AAAAA", suffix="BBBBB", error=False
    )
    payload = BreachCheckRequest(username="alice", password="password123")
    resp = await breach_check(_starlette_request(), payload)
    assert resp.breached is True
    assert resp.count == 5


@pytest.mark.asyncio
@patch("app.routers.breach.check_password_breach")
async def test_breach_check_safe(mock_check):
    from app.routers.breach import breach_check, BreachCheckRequest

    mock_check.return_value = MagicMock(
        breached=False, count=0, prefix="AAAAA", suffix="BBBBB", error=False
    )
    payload = BreachCheckRequest(username="alice", password="safe_password")
    resp = await breach_check(_starlette_request(), payload)
    assert resp.breached is False
    assert "not found" in resp.message


@pytest.mark.asyncio
@patch("app.routers.breach.check_password_breach")
async def test_breach_check_error_returns_503(mock_check):
    from app.routers.breach import breach_check, BreachCheckRequest
    from fastapi import HTTPException

    mock_check.return_value = MagicMock(
        breached=False, count=0, prefix="", suffix="", error=True
    )
    payload = BreachCheckRequest(username="alice", password="test")
    with pytest.raises(HTTPException) as exc_info:
        await breach_check(_starlette_request(), payload)
    assert exc_info.value.status_code == 503


# --- /api/score ---


@pytest.mark.asyncio
async def test_get_score_no_scans():
    from app.routers.breach import get_score
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await get_score("unknownuser123")
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_get_score_with_data(db):
    from app.routers.breach import get_score

    uid = get_or_create_user("scoreuser")
    scan_id = create_scan(uid)
    save_scan_result(scan_id, _make_fake_result(), probed_variant="test")
    finish_scan(scan_id)

    resp = await get_score("scoreuser")
    assert resp.score <= 850
    assert resp.core_accounts >= 1


# --- /api/verify ---


@pytest.mark.asyncio
@patch("app.osint.targets.fetch_all_targets", new_callable=AsyncMock)
@patch("app.osint.checker.classify_response")
@patch("app.osint.checker._build_url")
@patch("app.routers.breach.AsyncSession")
async def test_verify_not_found_reclaims_points(
    mock_session_cls, mock_build, mock_classify, mock_targets
):
    from app.routers.breach import verify_platform, VerifyRequest
    from app.osint.checker import Verdict

    target = MagicMock()
    target.platform_name = "GitHub"
    target.exists_status_code = 200
    target.is_core = True
    target.probe_url_template = "https://github.com/{account}"
    target.request_headers = {}
    mock_targets.return_value = [target]
    mock_build.return_value = "https://github.com/testuser"

    not_found_verdict = Verdict.NOT_FOUND
    mock_classify.return_value = (not_found_verdict, False, False, "not_found")

    uid = get_or_create_user("verifyuser")
    scan_id = create_scan(uid)
    save_scan_result(scan_id, _make_fake_result(), probed_variant="test")
    finish_scan(scan_id)

    # Mock the HTTP client
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    mock_resp.history = []
    mock_client_instance = AsyncMock()
    mock_client_instance.get = AsyncMock(return_value=mock_resp)
    mock_session_instance = AsyncMock()
    mock_session_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
    mock_session_instance.__aexit__ = AsyncMock(return_value=False)
    mock_session_cls.return_value = mock_session_instance

    payload = VerifyRequest(username="verifyuser", platform_name="GitHub")
    resp = await verify_platform(_starlette_request(), payload)
    assert resp.platform_name == "GitHub"
    assert resp.reclaimed_points >= 0


@pytest.mark.asyncio
@patch("app.osint.targets.fetch_all_targets", new_callable=AsyncMock)
async def test_verify_platform_not_found(mock_targets):
    from app.routers.breach import verify_platform, VerifyRequest
    from fastapi import HTTPException

    mock_targets.return_value = []
    payload = VerifyRequest(username="testuser", platform_name="NonExistent")
    with pytest.raises(HTTPException) as exc_info:
        await verify_platform(_starlette_request(), payload)
    assert exc_info.value.status_code == 404
