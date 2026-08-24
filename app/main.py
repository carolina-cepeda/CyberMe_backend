from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app import config
from app.db.database import init_db
from app.routers import auth, breach, scan

config.load_env()
init_db()

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="CyberMe API", version="0.2.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGINS = config.get_setting("CORS_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(breach.router)


@app.get("/api/health")
@limiter.exempt
async def health(request: Request) -> dict:
    return {"status": "ok"}


@app.get("/api/debug/db")
@limiter.exempt
async def debug_db(request: Request) -> dict:
    import os
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        return {"mode": "sqlite", "message": "No DATABASE_URL set, using SQLite"}
    stripped = url.strip()
    from urllib.parse import urlparse
    parsed = urlparse(stripped)
    result = {
        "mode": "postgres",
        "host": parsed.hostname or "unknown",
        "port": parsed.port or 5432,
        "database": (parsed.path or "").lstrip("/") or "unknown",
        "username": parsed.username or "unknown",
        "has_password": bool(parsed.password),
        "has_newline": "\n" in url,
        "has_trailing_space": url != url.rstrip(),
        "raw_length": len(url),
        "stripped_length": len(stripped),
    }
    try:
        import psycopg
    except ImportError:
        result["connection"] = "failed"
        result["error"] = "psycopg not installed"
        return result
    try:
        with psycopg.connect(stripped) as conn:
            row = conn.execute("SELECT current_database(), version()").fetchone()
            result["connection"] = "ok"
            result["connected_database"] = row[0]
            result["pg_version"] = row[1]
    except psycopg.Error as e:
        result["connection"] = "failed"
        result["error"] = str(e)
    except OSError as e:
        result["connection"] = "failed"
        result["error"] = str(e)
    return result
