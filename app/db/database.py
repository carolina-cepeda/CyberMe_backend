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
    detected INTEGER NOT NULL DEFAULT 0,
    inconclusive INTEGER NOT NULL DEFAULT 0,
    verdict_reason TEXT,
    exists_marker_matched INTEGER,
    miss_marker_matched INTEGER,
    category TEXT NOT NULL,
    is_core INTEGER NOT NULL DEFAULT 0,
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
                 exists_status_code, exists_marker, miss_marker, detected, inconclusive,
                 verdict_reason, exists_marker_matched, miss_marker_matched, category, is_core)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                int(result.detected),
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
