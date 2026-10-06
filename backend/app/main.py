"""
AdaptShield FastAPI Application Entrypoint.
===========================================
Provides REST and WebSocket endpoints for ransomware detection, simulation,
containment verification, dataset inspection, and ML model management.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.db.migrations import init_db
from backend.app.db.seed import seed_demo_data
from backend.app.services.system_state import SystemStateManager
from backend.app.api import api_router
from backend.app.api.stream import broadcaster

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("adaptshield.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for startup and shutdown procedures."""
    logger.info("Initializing AdaptShield backend...")
    # 1. Run SQLite migrations and ensure tables exist
    init_db()

    # 2. Auto-seed demo data on first launch
    seed_demo_data()

    # 3. Initialize state coordinator and subscribe broadcaster
    state = SystemStateManager.get_instance()
    broadcaster.subscribe_to_bus(state)

    logger.info("AdaptShield backend started successfully.")
    yield

    # Shutdown procedure
    logger.info("Shutting down AdaptShield backend...")
    state.stop_scenario()
    logger.info("Graceful shutdown complete.")


app = FastAPI(
    title="AdaptShield Backend API",
    description=(
        "Autonomous Linux ransomware detection & containment engine API. "
        "Provides scenario simulation, live detection pipeline, forensic alerts, "
        "model registry, and batched WebSocket event streams."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.server.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all API routes under /api
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "service": "AdaptShield API",
        "version": "0.1.0",
        "documentation": "/docs",
        "simulated": True,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=False,
    )
