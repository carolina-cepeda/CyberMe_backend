import asyncio
import logging
import re

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from app import config

limiter = Limiter(key_func=get_remote_address)
from app.db.database import (
    create_scan,
    finish_scan,
    get_or_create_user,
    get_previous_detected_platforms,
    save_scan_result,
    save_score,
)
from app.osint import checker, slugs, targets
from app.osint.official_apis import OfficialApiResult, run_official_api_checks
from app.osint.score import calculate_score

router = APIRouter(prefix="/api", tags=["scan"])
logger = logging.getLogger(__name__)


_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]{3,64}$")


class ScanRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    expand_names: bool = False

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        v = v.strip()
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username must be 3-64 chars, alphanumeric with . _ @ - only"
            )
        return v


class OfficialApiOut(BaseModel):
    platform: str
    exists: bool
    profile_url: str | None = None
    display_name: str | None = None
    bio: str | None = None
    created_at: str | None = None
    followers: int | None = None
    extra: dict | None = None


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
    official_apis: list[OfficialApiOut]
    score: int
    score_breakdown: dict


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


def _result_to_official_out(r: OfficialApiResult) -> OfficialApiOut:
    return OfficialApiOut(
        platform=r.platform,
        exists=r.exists,
        profile_url=r.profile_url,
        display_name=r.display_name,
        bio=r.bio,
        created_at=r.created_at,
        followers=r.followers,
        extra=r.extra,
    )


@router.post("/scan", response_model=ScanResponse)
@limiter.limit("5/minute")
async def run_scan(request: Request, payload: ScanRequest) -> ScanResponse:
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

    # Run official APIs + target fetching concurrently
    target_list_coro = targets.fetch_all_targets()
    official_api_coro = run_official_api_checks(primary_slug)
    target_list, official_results = await asyncio.gather(
        target_list_coro, official_api_coro
    )

    user_id = get_or_create_user(raw_input)
    scan_id = create_scan(user_id)

    # HTTP probe across all targets (WhatsMyName + Maigret)
    results = await checker.check_username(primary_slug, target_list)
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

    # Build detected platforms list for scoring
    detected_platforms = [
        {
            "platform_name": r.target.platform_name,
            "category": r.target.category,
            "is_core": r.target.is_core,
            "probed_url": r.requested_url,
        }
        for r in matches
    ]

    # Add official API detections as core platforms
    for api_result in official_results.values():
        if api_result.exists:
            detected_platforms.append({
                "platform_name": api_result.platform,
                "category": "social",
                "is_core": True,
                "probed_url": api_result.profile_url or "",
            })

    # Check breach status (if previously checked)
    from app.db.database import get_connection
    with get_connection() as conn:
        breach_row = conn.execute(
            "SELECT detected FROM breaches WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
    breach_detected = bool(breach_row and breach_row["detected"])

    # Get previous scan's detected platforms for reclamation
    previous_detected = get_previous_detected_platforms(scan_id)

    # Calculate score
    score_result = calculate_score(
        user_id=user_id,
        scan_id=scan_id,
        detected_platforms=detected_platforms,
        breach_detected=breach_detected,
        previous_detected=previous_detected,
    )
    save_score(user_id, scan_id, score_result.score)

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
        official_apis=[
            _result_to_official_out(r) for r in official_results.values()
        ],
        score=score_result.score,
        score_breakdown={
            "base": score_result.breakdown.base,
            "core_accounts": score_result.breakdown.core_accounts,
            "secondary_accounts": score_result.breakdown.secondary_accounts,
            "breach_detected": score_result.breakdown.breach_detected,
            "core_deduction": score_result.breakdown.core_deduction,
            "secondary_deduction": score_result.breakdown.secondary_deduction,
            "breach_deduction": score_result.breakdown.breach_deduction,
            "reclaimed": score_result.breakdown.reclaimed,
        },
    )
