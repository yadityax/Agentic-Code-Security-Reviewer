from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from backend.api.dashboard import router as dashboard_router
from backend.api.webhook import router as webhook_router
from backend.config import get_settings
from backend.services.telemetry import setup_telemetry

setup_telemetry("acsr-api")
app = FastAPI(title="Agentic Code Security Reviewer")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in get_settings().cors_origins.split(",") if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(webhook_router)
app.include_router(dashboard_router)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
