"""Breach check, scoring, and reclamation endpoints."""

import re

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.db.database import (
    get_detected_results,
    get_latest_breach,
    get_or_create_user,
    get_previous_detected_platforms,
    get_user_scans,
    mark_not_mine,
    save_breach_result,
    save_score,
    update_scan_result_verdict,
)
from app.osint.breach import check_password_breach
from app.osint.score import calculate_score

router = APIRouter(prefix="/api", tags=["breach"])
limiter = Limiter(key_func=get_remote_address)


# --- Request / Response models ---

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]{3,64}$")


class BreachCheckRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        v = v.strip()
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username must be 3-64 chars, alphanumeric with . _ @ - only"
            )
        return v


class BreachCheckResponse(BaseModel):
    breached: bool
    count: int
    message: str
    error: bool = False


class ScoreResponse(BaseModel):
    user_id: int | str
    score: int
    base: int
    core_accounts: int
    secondary_accounts: int
    breach_detected: bool
    core_deduction: int
    secondary_deduction: int
    breach_deduction: int
    reclaimed: int
    matches: int
    base_score: int = 850
    min_score: int = 300
    deduction_core: int = 30
    deduction_secondary: int = 15


class VerifyRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    platform_name: str = Field(..., min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        v = v.strip()
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username must be 3-64 chars, alphanumeric with . _ @ - only"
            )
        return v

    @field_validator("platform_name")
    @classmethod
    def sanitize_platform(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("Platform name must be 1-128 characters")
        return v


class VerifyResponse(BaseModel):
    verified: bool
    platform_name: str
    message: str
    reclaimed_points: int


class NotMineRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    platform_name: str = Field(..., min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        v = v.strip()
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username must be 3-64 chars, alphanumeric with . _ @ - only"
            )
        return v

    @field_validator("platform_name")
    @classmethod
    def sanitize_platform(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("Platform name must be 1-128 characters")
        return v


class NotMineResponse(BaseModel):
    success: bool
    platform_name: str
    score: int


# --- Endpoints ---

@router.post(
    "/breach",
    response_model=BreachCheckResponse,
    responses={
        400: {"description": "Validation error (missing password)"},
        503: {"description": "Breach check service unavailable"},
    },
)
@limiter.limit("10/minute")
async def breach_check(request: Request, payload: BreachCheckRequest) -> BreachCheckResponse:
    """Check if a password has appeared in known data breaches.

    Uses HIBP Pwned Passwords k-anonymity API.
    The password is SHA-1 hashed locally; only the first 5 hex chars
    are sent to the API.
    """
    if not payload.password:
        raise HTTPException(status_code=400, detail="Password required")

    async with AsyncSession(impersonate="chrome124") as client:
        result = await check_password_breach(client, payload.password)

    if result.error:
        raise HTTPException(
            status_code=503,
            detail="Breach check service unavailable. Please try again later.",
        )

    user_id = get_or_create_user(payload.username)
    save_breach_result(
        user_id=user_id,
        sha1_prefix=result.prefix,
        suffix_count=result.count,
        detected=result.breached,
    )

    if result.breached:
        msg = f"Password found in {result.count:,} data breaches"
    else:
        msg = "Password not found in known breaches"

    return BreachCheckResponse(
        breached=result.breached,
        count=result.count,
        message=msg,
    )


@router.get(
    "/score/{username}",
    response_model=ScoreResponse,
    responses={404: {"description": "No scans found for this user"}},
)
async def get_score(username: str) -> ScoreResponse:
    """Get the current Privacy Health Score for a user.

    Calculates based on the most recent scan results:
    - Core accounts detected: -30 each
    - Secondary accounts detected: -15 each
    - Password breach: -150
    - Minimum score: 300
    """
    user = get_or_create_user(username)
    scans = get_user_scans(user)
    if not scans:
        raise HTTPException(status_code=404, detail="No scans found for this user")

    latest_scan = scans[0]
    scan_id = latest_scan["id"]

    # Get detected platforms from the latest scan
    detected_platforms = get_detected_results(scan_id)

    # Check breach status
    breach_info = get_latest_breach(user)
    breach_detected = bool(breach_info and breach_info["detected"])

    # Get previous scan's detected platforms for reclamation
    previous = get_previous_detected_platforms(scan_id)

    score_result = calculate_score(
        user_id=user,
        scan_id=scan_id,
        detected_platforms=detected_platforms,
        breach_detected=breach_detected,
        previous_detected=previous,
    )

    # Persist the score
    save_score(user, scan_id, score_result.score)

    return ScoreResponse(
        user_id=user,
        score=score_result.score,
        base=score_result.breakdown.base,
        core_accounts=score_result.breakdown.core_accounts,
        secondary_accounts=score_result.breakdown.secondary_accounts,
        breach_detected=score_result.breakdown.breach_detected,
        core_deduction=score_result.breakdown.core_deduction,
        secondary_deduction=score_result.breakdown.secondary_deduction,
        breach_deduction=score_result.breakdown.breach_deduction,
        reclaimed=score_result.breakdown.reclaimed,
        matches=score_result.matches,
    )


@router.post(
    "/verify",
    response_model=VerifyResponse,
    responses={404: {"description": "Platform not found in targets"}},
)
@limiter.limit("10/minute")
async def verify_platform(request: Request, payload: VerifyRequest) -> VerifyResponse:
    """Re-verify a specific platform to check if an account still exists.

    If the platform returns NOT_FOUND, the previously deducted points
    are reclaimed and the live score is updated.
    """
    from app.osint.checker import Verdict, _build_url, classify_response
    from app.osint.targets import fetch_all_targets

    user_id = get_or_create_user(payload.username)

    # Find the target by platform name
    targets_list = await fetch_all_targets()
    target = None
    for t in targets_list:
        if t.platform_name == payload.platform_name:
            target = t
            break

    if target is None:
        raise HTTPException(status_code=404, detail="Platform not found in targets")

    # Build URL from target template (never use user-supplied URLs — SSRF prevention)
    probe_url = _build_url(target, payload.username)

    async with AsyncSession(impersonate="chrome124") as client:
        try:
            resp = await client.get(
                probe_url,
                headers=target.request_headers or None,
                impersonate="chrome124",
                allow_redirects=True,
            )
            first_hop = resp.history[0].status_code if resp.history else resp.status_code
            verdict, _, _, _ = classify_response(
                first_hop, resp.status_code, resp.text, target
            )
        except RequestsError:
            verdict = Verdict.UNREACHABLE

    reclaimed = 0
    if verdict is Verdict.NOT_FOUND:
        # Account no longer exists — reclaim points
        from app.osint.score import DEDUCTION_CORE, DEDUCTION_SECONDARY
        reclaimed = DEDUCTION_CORE if target.is_core else DEDUCTION_SECONDARY

        # Update the scan_results to mark this as not_found
        scans = get_user_scans(user_id)
        if scans:
            scan_id = scans[0]["id"]
            update_scan_result_verdict(scan_id, payload.platform_name, "not_found", 0)

            detected = get_detected_results(scan_id)
            breach_info = get_latest_breach(user_id)
            breach = bool(breach_info and breach_info["detected"])
            previous = get_previous_detected_platforms(scan_id)
            score_result = calculate_score(
                user_id=user_id, scan_id=scan_id,
                detected_platforms=detected, breach_detected=breach,
                previous_detected=previous,
            )
            save_score(user_id, scan_id, score_result.score)

    return VerifyResponse(
        verified=verdict is Verdict.DETECTED,
        platform_name=payload.platform_name,
        message=f"Account {'still exists' if verdict is Verdict.DETECTED else 'not found'} on {payload.platform_name}",
        reclaimed_points=reclaimed,
    )


@router.post(
    "/not-mine",
    response_model=NotMineResponse,
    responses={404: {"description": "Platform not found in latest scan"}},
)
@limiter.limit("10/minute")
async def not_mine(request: Request, payload: NotMineRequest) -> NotMineResponse:
    """Mark a detected platform as not belonging to the user.

    Excludes the platform from score calculations and recalculates.
    """
    user_id = get_or_create_user(payload.username)
    updated = mark_not_mine(user_id, payload.platform_name)

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Platform not found or not detected in latest scan",
        )

    # Recalculate score
    scans = get_user_scans(user_id)
    score_result = None
    if scans:
        scan_id = scans[0]["id"]
        detected = get_detected_results(scan_id)
        breach_info = get_latest_breach(user_id)
        breach = bool(breach_info and breach_info["detected"])
        previous = get_previous_detected_platforms(scan_id)
        score_result = calculate_score(
            user_id=user_id, scan_id=scan_id,
            detected_platforms=detected, breach_detected=breach,
            previous_detected=previous,
        )
        save_score(user_id, scan_id, score_result.score)

    return NotMineResponse(
        success=True,
        platform_name=payload.platform_name,
        score=score_result.score if score_result else 0,
    )
