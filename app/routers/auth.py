"""Supabase Auth proxy — signup and login."""

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

from app import config

router = APIRouter(prefix="/api/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)


class AuthSignupRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class AuthLoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    user_id: str
    email: str


class AuthErrorResponse(BaseModel):
    detail: str
    code: str = ""


async def _supabase_request(path: str, payload: dict) -> dict:
    """Make a request to Supabase Auth API."""
    supabase_url = config.get_setting("SUPABASE_URL")
    anon_key = config.get_setting("SUPABASE_ANON_KEY")

    if not supabase_url or not anon_key:
        raise HTTPException(
            status_code=503,
            detail="Supabase auth not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY.",
        )

    url = f"{supabase_url}/auth/v1{path}"
    headers = {
        "apikey": anon_key,
        "Content-Type": "application/json",
    }

    async with AsyncSession(impersonate="chrome124") as client:
        try:
            resp = await client.post(
                url,
                json=payload,
                headers=headers,
            )
        except RequestsError as e:
            logger.exception("Supabase request failed")
            raise HTTPException(
                status_code=503,
                detail=f"Auth service unavailable: {e}",
            )

    if resp.status_code >= 400:
        try:
            body = resp.json()
            msg = body.get("msg") or body.get("error_description") or str(body)
        except Exception:
            msg = resp.text or f"Supabase returned {resp.status_code}"
        raise HTTPException(status_code=401, detail=msg)

    return resp.json()


@router.post(
    "/signup",
    response_model=AuthResponse,
    responses={401: {"model": AuthErrorResponse}},
)
@limiter.limit("5/minute")
async def signup(request: Request, payload: AuthSignupRequest) -> AuthResponse:
    """Register a new user via Supabase Auth (email/password)."""
    data = await _supabase_request("/signup", {
        "email": payload.email,
        "password": payload.password,
    })

    user = data.get("user", {})
    return AuthResponse(
        access_token=data.get("access_token", ""),
        refresh_token=data.get("refresh_token", ""),
        user_id=user.get("id", ""),
        email=user.get("email", ""),
    )


@router.post(
    "/login",
    response_model=AuthResponse,
    responses={401: {"model": AuthErrorResponse}},
)
@limiter.limit("10/minute")
async def login(request: Request, payload: AuthLoginRequest) -> AuthResponse:
    """Log in via Supabase Auth (email/password)."""
    data = await _supabase_request("/token?grant_type=password", {
        "email": payload.email,
        "password": payload.password,
    })

    user = data.get("user", {})
    return AuthResponse(
        access_token=data.get("access_token", ""),
        refresh_token=data.get("refresh_token", ""),
        user_id=user.get("id", ""),
        email=user.get("email", ""),
    )
