"""SQLite persistence layer."""

import sqlite3
from datetime import datetime, timezone

from app import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    platform_name TEXT NOT NULL,
    probed_url TEXT NOT NULL,
    probed_variant TEXT NOT NULL DEFAULT '',
    observed_status_code INTEGER,
    exists_status_code INTEGER NOT NULL,
    exists_marker TEXT NOT NULL DEFAULT '',
    miss_marker TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT 'inconclusive',
    detected INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    inconclusive INTEGER NOT NULL DEFAULT 0,
    verdict_reason TEXT,
    exists_marker_matched INTEGER,
    miss_marker_matched INTEGER,
    category TEXT NOT NULL,
    is_core INTEGER NOT NULL DEFAULT 0,
    not_mine INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS breaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sha1_prefix TEXT NOT NULL,
    suffix_count INTEGER NOT NULL,
    detected INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    score INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_results_scan ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        # Migration: add not_mine column to existing databases
        try:
            conn.execute("ALTER TABLE scan_results ADD COLUMN not_mine INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists


def get_or_create_user(username: str) -> int:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO users (username, created_at) VALUES (?, ?)",
            (username, _now()),
        )
        return cur.lastrowid


def create_scan(user_id: int) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO scans (user_id, status, started_at) VALUES (?, ?, ?)",
            (user_id, "running", _now()),
        )
        return cur.lastrowid


def finish_scan(scan_id: int, status: str = "completed") -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, _now(), scan_id),
        )


def save_scan_result(scan_id: int, result, probed_variant: str = "") -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_results
                (scan_id, platform_name, probed_url, probed_variant, observed_status_code,
                 exists_status_code, exists_marker, miss_marker, verdict, detected, blocked,
                 inconclusive, verdict_reason, exists_marker_matched, miss_marker_matched,
                 category, is_core)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result.target.platform_name,
                result.requested_url,
                probed_variant,
                result.observed_status_code,
                result.target.exists_status_code,
                result.target.exists_marker,
                result.target.miss_marker,
                result.verdict.value,
                int(result.detected),
                int(result.blocked),
                int(result.inconclusive),
                result.verdict_reason,
                int(result.exists_marker_matched) if result.exists_marker_matched is not None else None,
                int(result.miss_marker_matched) if result.miss_marker_matched is not None else None,
                result.target.category,
                int(result.target.is_core),
            ),
        )


def get_user_scans(user_id: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC", (user_id,)
        ).fetchall()


def save_breach_result(
    user_id: int, sha1_prefix: str, suffix_count: int, detected: bool
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO breaches (user_id, sha1_prefix, suffix_count, detected, checked_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, sha1_prefix, suffix_count, int(detected), _now()),
        )


def save_score(user_id: int, scan_id: int, score: int) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scores (user_id, scan_id, score, created_at) VALUES (?, ?, ?, ?)",
            (user_id, scan_id, score, _now()),
        )


def get_latest_score(user_id: int) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scores WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if row:
            return dict(row)
        return None


def get_previous_detected_platforms(scan_id: int) -> set[str]:
    """Get platform names detected in a previous scan (for reclamation)."""
    with get_connection() as conn:
        # Get the scan before this one for the same user
        row = conn.execute(
            "SELECT user_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return set()
        user_id = row["user_id"]
        prev_row = conn.execute(
            """
            SELECT id FROM scans
            WHERE user_id = ? AND id < ? AND status = 'completed'
            ORDER BY id DESC LIMIT 1
            """,
            (user_id, scan_id),
        ).fetchone()
        if not prev_row:
            return set()
        rows = conn.execute(
            """
            SELECT platform_name FROM scan_results
            WHERE scan_id = ? AND detected = 1 AND not_mine = 0
            """,
            (prev_row["id"],),
        ).fetchall()
        return {r["platform_name"] for r in rows}


def mark_not_mine(user_id: int, platform_name: str) -> bool:
    """Mark a detected platform as not belonging to the user.

    Returns True if a row was updated.
    """
    with get_connection() as conn:
        # Find the latest completed scan for this user
        scan = conn.execute(
            """
            SELECT id FROM scans
            WHERE user_id = ? AND status = 'completed'
            ORDER BY id DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        if not scan:
            return False
        cur = conn.execute(
            """
            UPDATE scan_results SET not_mine = 1
            WHERE scan_id = ? AND platform_name = ? AND detected = 1
            """,
            (scan["id"], platform_name),
        )
        return cur.rowcount > 0
