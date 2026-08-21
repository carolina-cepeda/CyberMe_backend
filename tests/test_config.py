"""Tests for app.config."""

import os
from pathlib import Path

from app import config


def test_load_env_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / "nonexistent.env")
    config.load_env()  # should not raise


def test_load_env_with_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\n# comment\nEMPTY=\nBROKEN\n")
    monkeypatch.setattr(config, "ENV_FILE", env_file)
    monkeypatch.delenv("FOO", raising=False)
    config.load_env()
    assert os.environ.get("FOO") == "bar"


def test_get_setting_returns_default(monkeypatch):
    monkeypatch.delenv("CYBERME_TEST_KEY_XYZ", raising=False)
    assert config.get_setting("CYBERME_TEST_KEY_XYZ", "fallback") == "fallback"


def test_get_setting_returns_env(monkeypatch):
    monkeypatch.setenv("CYBERME_TEST_KEY_XYZ", "actual")
    assert config.get_setting("CYBERME_TEST_KEY_XYZ") == "actual"
