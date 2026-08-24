import logging
import os

import psycopg
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app import config
from app.db.database import init_db
from app.routers import auth, breach, scan

logger = logging.getLogger(__name__)

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


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": f"{type(exc).__name__}: {exc}"},
    )


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
        import psycopg as _psycopg
    except ImportError:
        result["connection"] = "failed"
        result["error"] = "psycopg not installed"
        return result
    try:
        with _psycopg.connect(stripped) as conn:
            row = conn.execute("SELECT current_database(), version()").fetchone()
            result["connection"] = "ok"
            result["connected_database"] = row[0]
            result["pg_version"] = row[1]
            tables = conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"
            ).fetchall()
            result["tables"] = [t[0] for t in tables]
    except (_psycopg.Error, OSError) as e:
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
    except ImportError as e:
        steps["imports"] = f"FAILED: {e}"
        return steps
    steps["imports"] = "ok"

    try:
        uid = get_or_create_user("__debugtest__")
        steps["get_or_create_user"] = f"ok (id={uid!r}, type={type(uid).__name__})"
    except (OSError, ValueError, psycopg.Error) as e:
        steps["get_or_create_user"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        scans = get_user_scans(uid)
        steps["get_user_scans"] = f"ok (count={len(scans)})"
    except (OSError, ValueError, psycopg.Error) as e:
        steps["get_user_scans"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        info = get_latest_breach(uid)
        steps["get_latest_breach"] = f"ok (result={info!r})"
    except (OSError, ValueError, psycopg.Error) as e:
        steps["get_latest_breach"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        results = get_detected_results(1)
        steps["get_detected_results"] = f"ok (count={len(results)})"
    except (OSError, ValueError, psycopg.Error) as e:
        steps["get_detected_results"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        scan_id = create_scan(uid)
        steps["create_scan"] = f"ok (scan_id={scan_id!r}, type={type(scan_id).__name__})"
        finish_scan(scan_id)
    except (OSError, ValueError, psycopg.Error) as e:
        steps["create_scan"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    try:
        save_score(uid, 1, 700)
        steps["save_score"] = "ok"
    except (OSError, ValueError, psycopg.Error) as e:
        steps["save_score"] = f"FAILED: {type(e).__name__}: {e}"
        return steps

    steps["all"] = "ALL PASSED"
    return steps


@app.get("/api/debug/schema")
@limiter.exempt
async def debug_schema(request: Request) -> dict:
    try:
        with psycopg.connect(os.environ["DATABASE_URL"].strip()) as conn:
            tables = conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"
            ).fetchall()
            result = {}
            for (tname,) in tables:
                cols = conn.execute(
                    "SELECT column_name, data_type, udt_name, "
                    "is_nullable, column_default "
                    "FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = %s "
                    "ORDER BY ordinal_position",
                    (tname,),
                ).fetchall()
                result[tname] = [
                    {"col": c[0], "type": c[1], "udt": c[2], "nullable": c[3], "default": c[4]}
                    for c in cols
                ]
                fks = conn.execute(
                    "SELECT tc.column_name, ccu.table_name AS ref_table, "
                    "ccu.column_name AS ref_column "
                    "FROM information_schema.table_constraints tc "
                    "JOIN information_schema.constraint_column_usage ccu "
                    "ON tc.constraint_name = ccu.constraint_name "
                    "WHERE tc.constraint_type = 'FOREIGN KEY' "
                    "AND tc.table_schema = 'public' AND tc.table_name = %s",
                    (tname,),
                ).fetchall()
                if fks:
                    result[tname + "_fks"] = [
                        {"col": f[0], "references": f"{f[1]}.{f[2]}"}
                        for f in fks
                    ]
            return result
    except (psycopg.Error, OSError) as e:
        return {"error": f"{type(e).__name__}: {e}"}
