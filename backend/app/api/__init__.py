"""
API Router aggregation for AdaptShield backend.
"""

from fastapi import APIRouter

from backend.app.api.status import router as status_router
from backend.app.api.processes import router as processes_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.scenarios import router as scenarios_router
from backend.app.api.datasets import router as datasets_router
from backend.app.api.models import router as models_router
from backend.app.api.settings import router as settings_router
from backend.app.api.stream import router as stream_router

api_router = APIRouter(prefix="/api")

api_router.include_router(status_router, tags=["Status & Control"])
api_router.include_router(processes_router, tags=["Processes"])
api_router.include_router(alerts_router, tags=["Alerts & Forensics"])
api_router.include_router(scenarios_router, tags=["Scenarios"])
api_router.include_router(datasets_router, tags=["Datasets"])
api_router.include_router(models_router, tags=["Models"])
api_router.include_router(settings_router, tags=["Settings"])
api_router.include_router(stream_router, tags=["Streaming"])

