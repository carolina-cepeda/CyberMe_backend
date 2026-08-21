"""Tests for app.osint.checker."""

import pytest

from app.osint.checker import Verdict, _build_url, classify_response, ProbeResult
from app.osint.targets import Target


def _target(**kwargs):
    defaults = dict(
        platform_name="GitHub",
        probe_url_template="https://github.com/{account}",
        exists_status_code=200,
        exists_marker='"login"',
        miss_status_code=None,
        miss_marker="Not Found",
        category="coding",
        is_core=True,
    )
    defaults.update(kwargs)
    return Target(**defaults)


# --- Verdict enum ---

def test_verdict_values():
    assert Verdict.DETECTED.value == "detected"
    assert Verdict.NOT_FOUND.value == "not_found"
    assert Verdict.BLOCKED.value == "blocked"
    assert Verdict.UNREACHABLE.value == "unreachable"
    assert Verdict.INCONCLUSIVE.value == "inconclusive"


# --- _build_url ---

def test_build_url_with_account_placeholder():
    t = _target()
    url = _build_url(t, "alice")
    assert url == "https://github.com/alice"


def test_build_url_with_empty_placeholder():
    t = _target(probe_url_template="https://example.com/{}")
    url = _build_url(t, "bob")
    assert url == "https://example.com/bob"


# --- classify_response ---

def test_classify_first_hop_none():
    t = _target()
    v, em, mm, reason = classify_response(None, None, "", t)
    assert v is Verdict.INCONCLUSIVE
    assert reason == "request_error"


def test_classify_protected_site():
    t = _target(protection=("login_walled",))
    v, _, _, reason = classify_response(200, 200, "", t)
    assert v is Verdict.INCONCLUSIVE
    assert reason == "protected"


def test_classify_miss_marker_present():
    t = _target()
    v, _, mm, reason = classify_response(200, 200, "Not Found", t)
    assert v is Verdict.NOT_FOUND
    assert mm is True
    assert reason == "miss_marker"


def test_classify_exists_status_match():
    t = _target()
    v, em, _, reason = classify_response(200, 200, '"login": "alice"', t)
    assert v is Verdict.DETECTED
    assert em is True


def test_classify_exists_status_no_marker():
    t = _target(exists_marker='"login"')
    v, _, _, reason = classify_response(200, 200, "no marker here", t)
    assert v is Verdict.INCONCLUSIVE
    assert reason == "exists_marker_absent"


def test_classify_miss_status_match():
    t = _target(miss_status_code=404)
    v, _, _, reason = classify_response(404, 404, "", t)
    assert v is Verdict.NOT_FOUND
    assert reason == "miss_status"


def test_classify_not_found_status():
    t = _target(exists_status_code=200)
    v, _, _, reason = classify_response(301, 404, "", t)
    assert v is Verdict.NOT_FOUND
    assert reason == "not_found_status"


def test_classify_blocked():
    t = _target(exists_status_code=200)
    v, _, _, reason = classify_response(403, 403, "", t)
    assert v is Verdict.BLOCKED
    assert reason == "bot_blocked"


def test_classify_inconclusive_unexpected():
    t = _target(exists_status_code=200)
    v, _, _, reason = classify_response(500, 500, "", t)
    assert v is Verdict.INCONCLUSIVE
    assert reason == "unexpected_status"


# --- ProbeResult properties ---

def test_probe_result_properties():
    t = _target()
    detected = ProbeResult(t, "url", 200, Verdict.DETECTED, True, False)
    assert detected.detected is True
    assert detected.blocked is False
    assert detected.unreachable is False
    assert detected.inconclusive is False

    blocked = ProbeResult(t, "url", 403, Verdict.BLOCKED, False, False)
    assert blocked.blocked is True

    unreachable = ProbeResult(t, "url", None, Verdict.UNREACHABLE, False, False)
    assert unreachable.unreachable is True

    inconclusive = ProbeResult(t, "url", 500, Verdict.INCONCLUSIVE, False, False)
    assert inconclusive.inconclusive is True
