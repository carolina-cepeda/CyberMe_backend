"""Tests for app.routers.scan (scan endpoint)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from starlette.requests import Request

from app.db.database import get_or_create_user


def _starlette_request():
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    return Request(scope)


def _make_fake_result(platform_name="GitHub", is_core=True):
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
    result.verdict.value = "detected"
    result.detected = True
    result.blocked = False
    result.inconclusive = False
    result.verdict_reason = None
    result.exists_marker_matched = True
    result.miss_marker_matched = False
    return result


@pytest.mark.asyncio
@patch("app.routers.scan.run_official_api_checks", new_callable=AsyncMock)
@patch("app.routers.scan.targets")
@patch("app.routers.scan.checker")
async def test_run_scan_basic(mock_checker, mock_targets, mock_official):
    from app.routers.scan import run_scan, ScanRequest

    mock_targets.fetch_all_targets = AsyncMock(return_value=[])
    mock_checker.check_username = AsyncMock(return_value=[])
    mock_official.return_value = {}

    payload = ScanRequest(username="testuser1")
    resp = await run_scan(_starlette_request(), payload)
    assert resp.username == "testuser1"
    assert resp.platforms_probed == 0
    assert resp.matches == 0
    assert resp.score == 850


@pytest.mark.asyncio
@patch("app.routers.scan.run_official_api_checks", new_callable=AsyncMock)
@patch("app.routers.scan.targets")
@patch("app.routers.scan.checker")
async def test_run_scan_with_matches(mock_checker, mock_targets, mock_official):
    from app.routers.scan import run_scan, ScanRequest

    mock_targets.fetch_all_targets = AsyncMock(return_value=[])
    mock_checker.check_username = AsyncMock(return_value=[_make_fake_result()])
    mock_official.return_value = {}

    payload = ScanRequest(username="founduser")
    resp = await run_scan(_starlette_request(), payload)
    assert resp.matches == 1
    assert resp.core_matches == 1
    assert resp.score < 850


@pytest.mark.asyncio
@patch("app.routers.scan.run_official_api_checks", new_callable=AsyncMock)
@patch("app.routers.scan.targets")
@patch("app.routers.scan.checker")
async def test_run_scan_with_official_api_hit(mock_checker, mock_targets, mock_official):
    from app.routers.scan import run_scan, ScanRequest

    mock_targets.fetch_all_targets = AsyncMock(return_value=[])
    mock_checker.check_username = AsyncMock(return_value=[])
    api_result = MagicMock()
    api_result.exists = True
    api_result.platform = "GitHub"
    api_result.profile_url = "https://github.com/testuser"
    api_result.display_name = "Test User"
    api_result.bio = None
    api_result.created_at = None
    api_result.followers = 0
    api_result.extra = {}
    mock_official.return_value = {"GitHub": api_result}

    payload = ScanRequest(username="apitestuser")
    resp = await run_scan(_starlette_request(), payload)
    assert resp.matches == 0
    assert len(resp.official_apis) == 1
    assert resp.score < 850


@pytest.mark.asyncio
@patch("app.routers.scan.run_official_api_checks", new_callable=AsyncMock)
@patch("app.routers.scan.targets")
@patch("app.routers.scan.checker")
async def test_run_scan_expand_names(mock_checker, mock_targets, mock_official):
    from app.routers.scan import run_scan, ScanRequest

    mock_targets.fetch_all_targets = AsyncMock(return_value=[])
    mock_checker.check_username = AsyncMock(return_value=[])
    mock_official.return_value = {}

    payload = ScanRequest(username="alice", expand_names=True)
    resp = await run_scan(_starlette_request(), payload)
    assert resp.primary_slug == "alice"


def test_result_to_official_out():
    from app.routers.scan import _result_to_official_out, OfficialApiOut

    r = MagicMock()
    r.platform = "GitHub"
    r.exists = True
    r.profile_url = "url"
    r.display_name = "name"
    r.bio = "bio"
    r.created_at = "2024-01-01"
    r.followers = 10
    r.extra = {"key": "val"}

    out = _result_to_official_out(r)
    assert isinstance(out, OfficialApiOut)
    assert out.platform == "GitHub"


@pytest.mark.asyncio
async def test_apply_fallback_passes():
    from app.routers.scan import _apply_fallback_passes
    from app.osint.checker import ProbeResult, Verdict
    from app.osint.targets import Target

    t = Target(
        platform_name="Test",
        probe_url_template="https://test.com/{account}",
        exists_status_code=200,
        exists_marker="found",
        miss_status_code=404,
        miss_marker="not found",
        category="coding",
        is_core=True,
    )
    results = [ProbeResult(t, "url", 404, Verdict.NOT_FOUND, False, False)]
    used = ["primary"]

    with patch("app.routers.scan.checker") as mock_checker:
        detected = ProbeResult(t, "url", 200, Verdict.DETECTED, True, False)
        mock_checker.check_username = AsyncMock(return_value=[detected])
        mock_checker.Verdict = Verdict
        await _apply_fallback_passes(results, ["primary", "fallback"], used)

    assert results[0].verdict is Verdict.DETECTED
    assert used[0] == "fallback"
