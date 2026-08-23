"""FastAPI dependencies for authentication."""

import logging

import jwt
from fastapi import Header, HTTPException
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

_SUPABASE_JWKS_URL = None
_jwk_client = None


def _get_jwk_client():
    global _SUPABASE_JWKS_URL, _jwk_client
    import os
    supabase_url = os.environ.get("SUPABASE_URL", "")
    if not supabase_url:
        return None
    url = f"{supabase_url}/auth/v1/.well-known/jwks.json"
    if _jwk_client is None or _SUPABASE_JWKS_URL != url:
        _SUPABASE_JWKS_URL = url
        _jwk_client = PyJWKClient(url, cache_jwk_set=True)
    return _jwk_client


def _verify_token(token: str) -> dict:
    """Verify a Supabase JWT and return the payload."""
    jwk = _get_jwk_client()
    if jwk is None:
        raise HTTPException(status_code=503, detail="Auth not configured")

    signing_key = jwk.get_signing_key_from_jwt(token)
    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["HS256"],
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return payload


async def get_current_user(authorization: str = Header(None)) -> dict:
    """FastAPI dependency: extract and verify the current user from Bearer token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization format")

    return _verify_token(parts[1])
