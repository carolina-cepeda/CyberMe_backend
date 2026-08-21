"""Shared fixtures for all tests."""

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _use_temp_db(tmp_path, monkeypatch):
    """Redirect DB_PATH to a temporary file and initialize tables for every test."""
    db_file = tmp_path / "test.db"
    monkeypatch.setattr("app.config.DB_PATH", db_file)
    from app.db.database import init_db
    init_db()
    return db_file


@pytest.fixture()
def db(_use_temp_db):
    """Return an initialized temporary database connection."""
    from app.db.database import get_connection
    conn = get_connection()
    yield conn
    conn.close()
