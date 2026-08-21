"""Tests for app.osint.slugs."""

from app.osint.slugs import build_variants, _ascii_fold


def test_ascii_fold_basic():
    assert _ascii_fold("John Doe") == "john doe"


def test_ascii_fold_accents():
    assert _ascii_fold("José García") == "jose garcia"


def test_single_word_no_fallbacks():
    assert build_variants("alice") == ["alice"]


def test_two_words_produces_separator_variants():
    variants = build_variants("John Doe")
    assert variants[0] == "johndoe"
    assert "john.doe" in variants
    assert "john_doe" in variants
    assert "john-doe" in variants


def test_max_fallbacks_capping():
    variants = build_variants("John Doe", max_fallbacks=1)
    assert len(variants) == 2  # primary + 1 fallback


def test_empty_string():
    assert build_variants("") == []
    assert build_variants("   ") == []
