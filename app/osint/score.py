"""Privacy Health Score calculator.

Scoring rules (from skill spec):
- Base: 850 (perfect privacy)
- Minimum: 300
- Exposed core account (social, tech, coding, etc.): -30 per match
- Exposed secondary account (forums, gaming, etc.): -15 per match
- Password breach detected (HIBP): -150
- Reclamation: if a previously detected URL returns NOT_FOUND, restore points
"""

from dataclasses import dataclass

BASE_SCORE = 850
MIN_SCORE = 300

# Deduction amounts
DEDUCTION_CORE = 30
DEDUCTION_SECONDARY = 15
DEDUCTION_BREACH = 150

# Categories considered "core" for scoring purposes
CORE_CATEGORIES = {
    "social",
    "tech",
    "coding",
    "business",
    "news",
    "blog",
    "video",
    "political",
}


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of how the score was calculated."""
    base: int = BASE_SCORE
    core_accounts: int = 0
    secondary_accounts: int = 0
    breach_detected: bool = False
    core_deduction: int = 0
    secondary_deduction: int = 0
    breach_deduction: int = 0
    reclaimed: int = 0
    final_score: int = BASE_SCORE

    @property
    def total_deduction(self) -> int:
        return self.core_deduction + self.secondary_deduction + self.breach_deduction - self.reclaimed


@dataclass
class ScanScore:
    """Complete score result for a scan."""
    user_id: int
    scan_id: int
    score: int
    breakdown: ScoreBreakdown
    matches: int = 0
    breach_exposed: bool = False


def calculate_score(
    user_id: int,
    scan_id: int,
    detected_platforms: list[dict],
    breach_detected: bool = False,
    previous_detected: set[str] | None = None,
) -> ScanScore:
    """Calculate the Privacy Health Score for a scan.

    Args:
        user_id: User ID in the database.
        scan_id: Current scan ID.
        detected_platforms: List of dicts with keys:
            - platform_name: str
            - category: str
            - is_core: bool
            - probed_url: str (for reclamation check)
        breach_detected: Whether the password was found in HIBP breaches.
        previous_detected: Set of platform_name strings that were detected
            in a prior scan (used for reclamation if now NOT_FOUND).

    Returns:
        ScanScore with the calculated score and breakdown.
    """
    breakdown = ScoreBreakdown(base=BASE_SCORE)

    for platform in detected_platforms:
        if platform.get("is_core"):
            breakdown.core_accounts += 1
        else:
            breakdown.secondary_accounts += 1

    breakdown.core_deduction = breakdown.core_accounts * DEDUCTION_CORE
    breakdown.secondary_deduction = breakdown.secondary_accounts * DEDUCTION_SECONDARY

    if breach_detected:
        breakdown.breach_detected = True
        breakdown.breach_deduction = DEDUCTION_BREACH

    # Reclamation: if a platform was previously detected but is now NOT_FOUND,
    # restore the points that were deducted for it.
    # This requires comparing with previous scan results.
    # For now, previous_detected is passed externally; a full implementation
    # would query the DB for the last scan's detected platforms.
    reclaimed_count = 0
    if previous_detected:
        current_names = {p["platform_name"] for p in detected_platforms}
        reclaimed_names = previous_detected - current_names
        reclaimed_count = len(reclaimed_names)
        # Restore points: count how many were core vs secondary
        # For simplicity, use the average deduction
        breakdown.reclaimed = reclaimed_count * DEDUCTION_CORE

    raw_score = (
        breakdown.base
        - breakdown.core_deduction
        - breakdown.secondary_deduction
        - breakdown.breach_deduction
        + breakdown.reclaimed
    )
    breakdown.final_score = max(MIN_SCORE, min(BASE_SCORE, raw_score))

    return ScanScore(
        user_id=user_id,
        scan_id=scan_id,
        score=breakdown.final_score,
        breakdown=breakdown,
        matches=len(detected_platforms),
        breach_exposed=breach_detected,
    )
