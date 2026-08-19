import asyncio

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app import config
from app.db.database import (
    create_scan,
    finish_scan,
    get_or_create_user,
    save_scan_result,
)
from app.osint import checker, slugs, targets
from app.osint.control import run_control_scan

router = APIRouter(prefix="/api", tags=["scan"])


class ScanRequest(BaseModel):
    username: str
    expand_names: bool = False


class ScanResponse(BaseModel):
    scan_id: int
    username: str
    primary_slug: str
    variants_used: list[str]
    platforms_probed: int
    matches: int
    core_matches: int
    secondary_matches: int
    blocked: int
    unreachable: int
    inconclusive: int


async def _apply_fallback_passes(
    results: list[checker.ProbeResult],
    variants: list[str],
    used_variants: list[str],
) -> None:
    """Probe fallback slug variants only on platforms that missed the primary.

    Mutates `results` in place when a fallback variant detects an account.
    """
    for variant in variants[1:]:
        indices = [
            i
            for i, r in enumerate(results)
            if r.verdict is checker.Verdict.NOT_FOUND
        ]
        if not indices:
            break
        targets_to_reprobe = [results[i].target for i in indices]
        fallback_results = await checker.check_username(variant, targets_to_reprobe)
        for index, fallback in zip(indices, fallback_results):
            if fallback.detected:
                results[index] = fallback
                used_variants[index] = variant


@router.post("/scan", response_model=ScanResponse)
async def run_scan(payload: ScanRequest) -> ScanResponse:
    raw_input = payload.username.strip()
    if not raw_input or len(raw_input) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")

    if " " in raw_input or payload.expand_names:
        variants = slugs.build_variants(
            raw_input, max_fallbacks=config.MAX_NAME_FALLBACK_VARIANTS
        )
    else:
        variants = [raw_input]
    if not variants:
        raise HTTPException(status_code=400, detail="No usable name or username supplied")

    primary_slug = variants[0]
    target_list = await targets.fetch_targets()
    user_id = get_or_create_user(raw_input)
    scan_id = create_scan(user_id)

    # TODO(remove): control scan only for temporary FPR diagnostics.
    results, control = await asyncio.gather(
        checker.check_username(primary_slug, target_list),
        run_control_scan(target_list),
    )
    used_variants = [primary_slug] * len(results)
    await _apply_fallback_passes(results, variants, used_variants)

    try:
        for result, variant in zip(results, used_variants):
            save_scan_result(scan_id, result, probed_variant=variant)
    finally:
        finish_scan(scan_id)

    matches = [r for r in results if r.detected]
    core_matches = sum(1 for r in matches if r.target.is_core)
    secondary_matches = sum(1 for r in matches if not r.target.is_core)
    probed = len(results)
    blocked = sum(1 for r in results if r.blocked)
    unreachable = sum(1 for r in results if r.unreachable)
    inconclusive = sum(1 for r in results if r.inconclusive)

    # TODO(remove): temporary statistics print.
    print(
        f"[SCAN-STATS] username={raw_input} slug={primary_slug} variants={sorted(set(used_variants))} "
        f"probed={probed} matches={len(matches)} core={core_matches} secondary={secondary_matches} "
        f"blocked={blocked} unreachable={unreachable} inconclusive={inconclusive} "
        f"detection_rate={(len(matches) / probed * 100) if probed else 0:.1f}%"
    )
    print(
        f"[SCAN-STATS] FPR: control={control.control_username} "
        f"probed={control.probed} fp={control.false_positives} "
        f"fpr={control.fpr * 100:.1f}%"
    )

    return ScanResponse(
        scan_id=scan_id,
        username=raw_input,
        primary_slug=primary_slug,
        variants_used=sorted(set(used_variants)),
        platforms_probed=probed,
        matches=len(matches),
        core_matches=core_matches,
        secondary_matches=secondary_matches,
        blocked=blocked,
        unreachable=unreachable,
        inconclusive=inconclusive,
    )
