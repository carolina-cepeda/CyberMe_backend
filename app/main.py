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
    result: dict = {
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
            tables = conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"
            ).fetchall()
            result["tables"] = [t[0] for t in tables]
    except psycopg.Error as e:
        result["connection"] = "failed"
        result["error"] = str(e)
    except OSError as e:
        result["connection"] = "failed"
        result["error"] = str(e)
    return result


@app.get("/api/debug/test-db")
@limiter.exempt
async def debug_test_db(request: Request) -> dict:
    steps: dict = {}
    try:
        from app.db.database import (
            create_scan,
            finish_scan,
            get_detected_results,
            get_latest_breach,
            get_or_create_user,
            get_user_scans,
            save_score,
        )
        steps["imports"] = "ok"
    except ImportError as e:
        steps["imports"] = f"FAILED: {e}"
        return steps

    try:
        uid = get_or_create_user("__debugtest__")
        steps["get_or_create_user"] = f"ok (id={uid!r}, type={type(uid).__name__})"
    except (OSError, ValueError) as e:
        steps["get_or_create_user"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        scans = get_user_scans(uid)
        steps["get_user_scans"] = f"ok (count={len(scans)})"
    except (OSError, ValueError) as e:
        steps["get_user_scans"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        info = get_latest_breach(uid)
        steps["get_latest_breach"] = f"ok (result={info!r})"
    except (OSError, ValueError) as e:
        steps["get_latest_breach"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        results = get_detected_results(1)
        steps["get_detected_results"] = f"ok (count={len(results)})"
    except (OSError, ValueError) as e:
        steps["get_detected_results"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        scan_id = create_scan(uid)
        steps["create_scan"] = f"ok (scan_id={scan_id!r}, type={type(scan_id).__name__})"
        finish_scan(scan_id)
    except (OSError, ValueError) as e:
        steps["create_scan"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        save_score(uid, 1, 700)
        steps["save_score"] = "ok"
    except (OSError, ValueError) as e:
        steps["save_score"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    steps["all"] = "ALL PASSED"
    return steps
