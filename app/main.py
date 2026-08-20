from fastapi import FastAPI

from app import config
from app.db.database import init_db
from app.routers import scan, breach

config.load_env()
init_db()

app = FastAPI(title="CyberMe API", version="0.1.0")
app.include_router(scan.router)
app.include_router(breach.router)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}
