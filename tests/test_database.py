"""Tests for app.db.database."""

import sqlite3

from app.db.database import (
    create_scan,
    finish_scan,
    get_connection,
    get_latest_score,
    get_or_create_user,
    get_previous_detected_platforms,
    get_user_scans,
    init_db,
    mark_not_mine,
    save_breach_result,
    save_score,
)


def _make_fake_result():
    """Build a minimal mock ProbeResult for save_scan_result."""
    from unittest.mock import MagicMock

    target = MagicMock()
    target.platform_name = "GitHub"
    target.exists_status_code = 200
    target.exists_marker = '"login"'
    target.miss_marker = ""
    target.category = "coding"
    target.is_core = True

    result = MagicMock()
    result.target = target
    result.requested_url = "https://github.com/testuser"
    result.observed_status_code = 200
    result.verdict.value = "detected"
    result.detected = True
    result.blocked = False
    result.inconclusive = False
    result.verdict_reason = None
    result.exists_marker_matched = True
    result.miss_marker_matched = False
    return result


def test_init_db_creates_tables(db):
    tables = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    names = {t["name"] for t in tables}
    assert "users" in names
    assert "scans" in names
    assert "scan_results" in names
    assert "breaches" in names
    assert "scores" in names


def test_get_or_create_user_new(db):
    uid = get_or_create_user("alice")
    assert uid >= 1


def test_get_or_create_user_existing(db):
    uid1 = get_or_create_user("alice")
    uid2 = get_or_create_user("alice")
    assert uid1 == uid2


def test_create_and_finish_scan(db):
    uid = get_or_create_user("bob")
    scan_id = create_scan(uid)
    assert scan_id >= 1
    finish_scan(scan_id)
    row = db.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    assert row["status"] == "completed"


def test_save_scan_result(db):
    uid = get_or_create_user("test")
    scan_id = create_scan(uid)
    from app.db.database import save_scan_result as _save
    _save(scan_id, _make_fake_result(), probed_variant="testuser")
    row = db.execute("SELECT * FROM scan_results WHERE scan_id=?", (scan_id,)).fetchone()
    assert row is not None
    assert row["platform_name"] == "GitHub"


def test_get_user_scans(db):
    uid = get_or_create_user("scanuser")
    scan_id = create_scan(uid)
    finish_scan(scan_id)
    scans = get_user_scans(uid)
    assert len(scans) == 1
    assert scans[0]["id"] == scan_id


def test_save_breach_result(db):
    uid = get_or_create_user("breachuser")
    save_breach_result(uid, "AAAAA", 10, True)
    row = db.execute("SELECT * FROM breaches WHERE user_id=?", (uid,)).fetchone()
    assert row is not None
    assert row["detected"] == 1


def test_save_and_get_latest_score(db):
    uid = get_or_create_user("scoreuser")
    scan_id = create_scan(uid)
    finish_scan(scan_id)
    save_score(uid, scan_id, 720)
    latest = get_latest_score(uid)
    assert latest is not None
    assert latest["score"] == 720


def test_get_latest_score_none(db):
    uid = get_or_create_user("noscore")
    assert get_latest_score(uid) is None


def test_get_previous_detected_platforms_empty(db):
    uid = get_or_create_user("prev")
    scan_id = create_scan(uid)
    finish_scan(scan_id)
    prev = get_previous_detected_platforms(scan_id)
    assert prev == set()


def test_get_previous_detected_platforms_with_data(db):
    uid = get_or_create_user("prev2")
    scan1 = create_scan(uid)
    from app.db.database import save_scan_result as _save
    _save(scan1, _make_fake_result(), probed_variant="test")
    finish_scan(scan1)

    scan2 = create_scan(uid)
    finish_scan(scan2)

    prev = get_previous_detected_platforms(scan2)
    assert "GitHub" in prev


def test_mark_not_mine_updates_row(db):
    uid = get_or_create_user("notmine")
    scan_id = create_scan(uid)
    from app.db.database import save_scan_result as _save
    _save(scan_id, _make_fake_result(), probed_variant="test")
    finish_scan(scan_id)

    result = mark_not_mine(uid, "GitHub")
    assert result is True

    row = db.execute(
        "SELECT not_mine FROM scan_results WHERE scan_id = ? AND platform_name = ?",
        (scan_id, "GitHub"),
    ).fetchone()
    assert row["not_mine"] == 1


def test_mark_not_mine_no_scan_returns_false(db):
    uid = get_or_create_user("noscan")
    result = mark_not_mine(uid, "GitHub")
    assert result is False


def test_mark_not_mine_platform_not_found_returns_false(db):
    uid = get_or_create_user("notfound")
    scan_id = create_scan(uid)
    from app.db.database import save_scan_result as _save
    _save(scan_id, _make_fake_result(), probed_variant="test")
    finish_scan(scan_id)

    result = mark_not_mine(uid, "NonExistent")
    assert result is False
