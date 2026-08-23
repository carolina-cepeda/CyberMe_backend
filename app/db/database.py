"""Dual-mode persistence: SQLite (local/dev) or Postgres (production via Supabase)."""

import sqlite3
import os
from datetime import datetime, timezone

from app import config


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_postgres() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


# ---------------------------------------------------------------------------
# SQLite path (local dev / tests)
# ---------------------------------------------------------------------------

SQLITE_SCHEMA = """
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

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT,
    created_at TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::text
);

CREATE TABLE IF NOT EXISTS scans (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::text,
    finished_at TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);

CREATE TABLE IF NOT EXISTS scan_results (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    platform_name TEXT NOT NULL,
    probed_url TEXT NOT NULL,
    probed_variant TEXT DEFAULT '',
    observed_status_code INTEGER NULL,
    exists_status_code INTEGER NOT NULL,
    exists_marker TEXT DEFAULT '',
    miss_marker TEXT DEFAULT '',
    verdict TEXT DEFAULT 'inconclusive',
    detected INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0,
    inconclusive INTEGER DEFAULT 0,
    verdict_reason TEXT NULL,
    exists_marker_matched INTEGER NULL,
    miss_marker_matched INTEGER NULL,
    category TEXT NOT NULL,
    is_core INTEGER DEFAULT 0,
    not_mine INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON scan_results(scan_id);

CREATE TABLE IF NOT EXISTS breaches (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sha1_prefix TEXT NOT NULL,
    suffix_count INTEGER NOT NULL,
    detected INTEGER DEFAULT 0,
    checked_at TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::text
);

CREATE TABLE IF NOT EXISTS scores (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::text
);
"""


def _pg_conn():
    import psycopg
    return psycopg.connect(os.environ["DATABASE_URL"])


# ---------------------------------------------------------------------------
# SQLite connection
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    if _is_postgres():
        raise RuntimeError("get_connection() is for SQLite only; use _pg_conn()")
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    if _is_postgres():
        with _pg_conn() as conn:
            conn.execute(POSTGRES_SCHEMA)
            conn.commit()
    else:
        with get_connection() as conn:
            conn.executescript(SQLITE_SCHEMA)
            try:
                conn.execute("ALTER TABLE scan_results ADD COLUMN not_mine INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass


# ---------------------------------------------------------------------------
# User operations
# ---------------------------------------------------------------------------

def get_or_create_user(username: str, user_id: str | None = None) -> int | str:
    """Get or create user. Returns int (SQLite) or str UUID (Postgres)."""
    if _is_postgres():
        with _pg_conn() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = %s", (username,)
            ).fetchone()
            if row:
                return row[0]
            uid = user_id or username
            conn.execute(
                "INSERT INTO users (id, username, created_at) VALUES (%s, %s, %s) ON CONFLICT (username) DO NOTHING",
                (uid, username, _now()),
            )
            conn.commit()
            row = conn.execute(
                "SELECT id FROM users WHERE username = %s", (username,)
            ).fetchone()
            return row[0] if row else uid
    else:
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


# ---------------------------------------------------------------------------
# Scan operations
# ---------------------------------------------------------------------------

def create_scan(user_id: int | str) -> int:
    if _is_postgres():
        with _pg_conn() as conn:
            row = conn.execute(
                "INSERT INTO scans (user_id, status, started_at) VALUES (%s, %s, %s) RETURNING id",
                (user_id, "running", _now()),
            ).fetchone()
            conn.commit()
            return row[0]
    else:
        with get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO scans (user_id, status, started_at) VALUES (?, ?, ?)",
                (user_id, "running", _now()),
            )
            return cur.lastrowid


def finish_scan(scan_id: int, status: str = "completed") -> None:
    if _is_postgres():
        with _pg_conn() as conn:
            conn.execute(
                "UPDATE scans SET status = %s, finished_at = %s WHERE id = %s",
                (status, _now(), scan_id),
            )
            conn.commit()
    else:
        with get_connection() as conn:
            conn.execute(
                "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
                (status, _now(), scan_id),
            )


def save_scan_result(scan_id: int, result, probed_variant: str = "") -> None:
    values = (
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
    )

    if _is_postgres():
        with _pg_conn() as conn:
            conn.execute(
                """
                INSERT INTO scan_results
                    (scan_id, platform_name, probed_url, probed_variant, observed_status_code,
                     exists_status_code, exists_marker, miss_marker, verdict, detected, blocked,
                     inconclusive, verdict_reason, exists_marker_matched, miss_marker_matched,
                     category, is_core)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                values,
            )
            conn.commit()
    else:
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
                values,
            )


def get_user_scans(user_id: int | str) -> list:
    if _is_postgres():
        with _pg_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE user_id = %s ORDER BY id DESC", (user_id,)
            ).fetchall()
            # Return dict-like rows for compatibility
            return [dict(zip([d[0] for d in row.description], row)) for row in rows]
    else:
        with get_connection() as conn:
            return conn.execute(
                "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC", (user_id,)
            ).fetchall()


def save_breach_result(
    user_id: int | str, sha1_prefix: str, suffix_count: int, detected: bool
) -> None:
    if _is_postgres():
        with _pg_conn() as conn:
            conn.execute(
                """
                INSERT INTO breaches (user_id, sha1_prefix, suffix_count, detected, checked_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, sha1_prefix, suffix_count, int(detected), _now()),
            )
            conn.commit()
    else:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO breaches (user_id, sha1_prefix, suffix_count, detected, checked_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, sha1_prefix, suffix_count, int(detected), _now()),
            )


def save_score(user_id: int | str, scan_id: int, score: int) -> None:
    if _is_postgres():
        with _pg_conn() as conn:
            conn.execute(
                "INSERT INTO scores (user_id, scan_id, score, created_at) VALUES (%s, %s, %s, %s)",
                (user_id, scan_id, score, _now()),
            )
            conn.commit()
    else:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO scores (user_id, scan_id, score, created_at) VALUES (?, ?, ?, ?)",
                (user_id, scan_id, score, _now()),
            )


def get_latest_score(user_id: int | str) -> dict | None:
    if _is_postgres():
        with _pg_conn() as conn:
            row = conn.execute(
                "SELECT * FROM scores WHERE user_id = %s ORDER BY id DESC LIMIT 1",
                (user_id,),
            ).fetchone()
            return dict(row) if row else None
    else:
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
    if _is_postgres():
        with _pg_conn() as conn:
            row = conn.execute(
                "SELECT user_id FROM scans WHERE id = %s", (scan_id,)
            ).fetchone()
            if not row:
                return set()
            user_id = row[0]
            prev = conn.execute(
                """
                SELECT id FROM scans
                WHERE user_id = %s AND id < %s AND status = 'completed'
                ORDER BY id DESC LIMIT 1
                """,
                (user_id, scan_id),
            ).fetchone()
            if not prev:
                return set()
            rows = conn.execute(
                """
                SELECT platform_name FROM scan_results
                WHERE scan_id = %s AND detected = 1 AND not_mine = 0
                """,
                (prev[0],),
            ).fetchall()
            return {r[0] for r in rows}
    else:
        with get_connection() as conn:
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


def mark_not_mine(user_id: int | str, platform_name: str) -> bool:
    """Mark a detected platform as not belonging to the user."""
    if _is_postgres():
        with _pg_conn() as conn:
            scan = conn.execute(
                """
                SELECT id FROM scans
                WHERE user_id = %s AND status = 'completed'
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            if not scan:
                return False
            cur = conn.execute(
                """
                UPDATE scan_results SET not_mine = 1
                WHERE scan_id = %s AND platform_name = %s AND detected = 1
                """,
                (scan[0], platform_name),
            )
            conn.commit()
            return cur.rowcount > 0
    else:
        with get_connection() as conn:
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


def get_latest_breach(user_id: int | str) -> dict | None:
    """Get the latest breach record for a user."""
    if _is_postgres():
        with _pg_conn() as conn:
            row = conn.execute(
                "SELECT detected FROM breaches WHERE user_id = %s ORDER BY id DESC LIMIT 1",
                (user_id,),
            ).fetchone()
            return {"detected": row[0]} if row else None
    else:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT detected FROM breaches WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (user_id,),
            ).fetchone()
            return {"detected": row["detected"]} if row else None


def get_detected_results(scan_id: int) -> list[dict]:
    """Get detected results for a scan."""
    if _is_postgres():
        with _pg_conn() as conn:
            rows = conn.execute(
                """
                SELECT platform_name, category, is_core, probed_url
                FROM scan_results WHERE scan_id = %s AND detected = 1 AND not_mine = 0
                """,
                (scan_id,),
            ).fetchall()
            return [dict(zip([d[0] for d in r.description], r)) for r in rows]
    else:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT platform_name, category, is_core, probed_url
                FROM scan_results WHERE scan_id = ? AND detected = 1 AND not_mine = 0
                """,
                (scan_id,),
            ).fetchall()
            return [dict(r) for r in rows]


def update_scan_result_verdict(
    scan_id: int, platform_name: str, verdict: str, detected: int
) -> None:
    """Update a scan result's verdict and detected status."""
    if _is_postgres():
        with _pg_conn() as conn:
            conn.execute(
                """
                UPDATE scan_results SET detected = %s, verdict = %s
                WHERE scan_id = %s AND platform_name = %s
                """,
                (detected, verdict, scan_id, platform_name),
            )
            conn.commit()
    else:
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE scan_results SET detected = ?, verdict = ?
                WHERE scan_id = ? AND platform_name = ?
                """,
                (detected, verdict, scan_id, platform_name),
            )
