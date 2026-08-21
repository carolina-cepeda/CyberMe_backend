"""Tests for app.osint.score."""

from app.osint.score import (
    BASE_SCORE,
    DEDUCTION_BREACH,
    DEDUCTION_CORE,
    DEDUCTION_SECONDARY,
    MIN_SCORE,
    ScoreBreakdown,
    ScanScore,
    calculate_score,
)


def test_no_detections_returns_base_score():
    result = calculate_score(user_id=1, scan_id=1, detected_platforms=[])
    assert result.score == BASE_SCORE
    assert result.matches == 0
    assert result.breakdown.core_accounts == 0


def test_core_deduction():
    platforms = [
        {"platform_name": "GitHub", "category": "coding", "is_core": True, "probed_url": "u"},
        {"platform_name": "Twitter", "category": "social", "is_core": True, "probed_url": "u"},
    ]
    result = calculate_score(user_id=1, scan_id=1, detected_platforms=platforms)
    assert result.breakdown.core_accounts == 2
    assert result.breakdown.core_deduction == 2 * DEDUCTION_CORE
    assert result.score == BASE_SCORE - 2 * DEDUCTION_CORE


def test_secondary_deduction():
    platforms = [
        {"platform_name": "Forum", "category": "forum", "is_core": False, "probed_url": "u"},
    ]
    result = calculate_score(user_id=1, scan_id=1, detected_platforms=platforms)
    assert result.breakdown.secondary_accounts == 1
    assert result.breakdown.secondary_deduction == DEDUCTION_SECONDARY


def test_breach_deduction():
    platforms = []
    result = calculate_score(
        user_id=1, scan_id=1, detected_platforms=platforms, breach_detected=True
    )
    assert result.breakdown.breach_detected is True
    assert result.breakdown.breach_deduction == DEDUCTION_BREACH
    assert result.score == BASE_SCORE - DEDUCTION_BREACH


def test_score_minimum_floor():
    platforms = [{"platform_name": f"P{i}", "category": "social", "is_core": True, "probed_url": "u"} for i in range(30)]
    result = calculate_score(user_id=1, scan_id=1, detected_platforms=platforms)
    assert result.score == MIN_SCORE


def test_reclamation_restores_points():
    platforms = [
        {"platform_name": "GitHub", "category": "coding", "is_core": True, "probed_url": "u"},
    ]
    previous = {"GitHub", "Twitter"}
    result = calculate_score(
        user_id=1, scan_id=1,
        detected_platforms=platforms,
        previous_detected=previous,
    )
    assert result.breakdown.reclaimed > 0


def test_score_never_exceeds_base():
    platforms = []
    previous = {"OldPlatform"}
    result = calculate_score(
        user_id=1, scan_id=1,
        detected_platforms=platforms,
        previous_detected=previous,
    )
    assert result.score <= BASE_SCORE


def test_breakdown_total_deduction():
    b = ScoreBreakdown(
        core_deduction=60,
        secondary_deduction=15,
        breach_deduction=150,
        reclaimed=30,
    )
    assert b.total_deduction == 60 + 15 + 150 - 30
