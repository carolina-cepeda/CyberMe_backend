"""Tests for app.osint.maigret_adapter."""

from unittest.mock import patch, mock_open
import json

from app.osint.maigret_adapter import _pick_category, _convert_site, load_maigret_targets


def test_pick_category_known():
    assert _pick_category(["social"]) == "social"
    assert _pick_category(["coding"]) == "coding"
    assert _pick_category(["gaming"]) == "gaming"


def test_pick_category_unknown():
    assert _pick_category(["randomtag"]) == "general"


def test_pick_category_empty():
    assert _pick_category([]) == "general"


def test_convert_site_valid():
    site = {
        "urlProbe": "https://example.com/{username}",
        "presenseStrs": ["Found"],
        "absenceStrs": ["Not Found"],
        "checkType": "message",
        "tags": ["social"],
        "headers": {"X-Custom": "val"},
    }
    target = _convert_site("ExampleSite", site)
    assert target is not None
    assert target.platform_name == "ExampleSite"
    assert target.exists_marker == "Found"
    assert target.miss_marker == "Not Found"
    assert target.category == "social"
    assert target.request_headers == {"X-Custom": "val"}


def test_convert_site_no_probe_url():
    site = {"presenseStrs": ["Found"]}
    assert _convert_site("X", site) is None


def test_convert_site_no_username_placeholder():
    site = {"urlProbe": "https://example.com/static", "presenseStrs": ["Found"]}
    assert _convert_site("X", site) is None


def test_convert_site_no_presence_marker():
    site = {
        "urlProbe": "https://example.com/{username}",
        "presenseStrs": [],
        "absenceStrs": [],
    }
    assert _convert_site("X", site) is None


def test_convert_site_status_code_check_type():
    site = {
        "urlProbe": "https://example.com/{username}",
        "presenseStrs": ["OK"],
        "checkType": "status_code",
    }
    target = _convert_site("StatusSite", site)
    assert target is not None
    assert target.exists_status_code == 200


def test_load_maigret_targets_missing_file(monkeypatch):
    from app.osint.maigret_adapter import _MAIGRET_DATA_PATH
    monkeypatch.setattr(
        "app.osint.maigret_adapter._MAIGRET_DATA_PATH",
        _MAIGRET_DATA_PATH.parent / "nonexistent.json",
    )
    assert load_maigret_targets() == []


def test_load_maigret_targets_filters_duplicates(tmp_path, monkeypatch):
    data = {
        "sites": {
            "GitHub": {
                "urlProbe": "https://github.com/{username}",
                "presenseStrs": ["login"],
                "tags": ["coding"],
            }
        }
    }
    fake_path = tmp_path / "data.json"
    fake_path.write_text(json.dumps(data))
    monkeypatch.setattr("app.osint.maigret_adapter._MAIGRET_DATA_PATH", fake_path)

    targets = load_maigret_targets(existing_names={"GitHub"})
    assert len(targets) == 0
