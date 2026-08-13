"""Temporary FPR estimation via a control scan (diagnostics, remove later)."""

from dataclasses import dataclass

from app.osint import checker
from app.osint.targets import Target


@dataclass
class ControlScanStats:
    control_username: str
    probed: int
    false_positives: int
    fpr: float


# TODO(remove): temporary diagnostic helper.
async def run_control_scan(targets: list[Target]) -> ControlScanStats:
    username = checker.generate_control_username()
    results = await checker.check_username(username, targets)
    hits = sum(1 for r in results if r.detected)
    probed = len(results)
    fpr = (hits / probed) if probed else 0.0
    return ControlScanStats(
        control_username=username,
        probed=probed,
        false_positives=hits,
        fpr=fpr,
    )
