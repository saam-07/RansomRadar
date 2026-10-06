"""
Settings and demo environment reset endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter
from backend.app.schemas import SettingsResponse, SettingsUpdateRequest
from backend.app.services.system_state import SystemStateManager

router = APIRouter()


@router.get("/settings", response_model=SettingsResponse)
def get_settings():
    """Retrieves active detection, threshold, and safety rail configurations."""
    state = SystemStateManager.get_instance()
    cfg = state.get_settings()
    return SettingsResponse(**cfg)


@router.post("/settings", response_model=SettingsResponse)
@router.put("/settings", response_model=SettingsResponse)
def update_settings(payload: SettingsUpdateRequest):
    """Updates runtime engine parameters, allowlist, and policy thresholds."""
    state = SystemStateManager.get_instance()
    updates = payload.dict(exclude_unset=True)
    cfg = state.update_settings(updates)
    return SettingsResponse(**cfg)


@router.post("/settings/reset")
def reset_demo_state():
    """Resets simulator filesystem, stops scenarios, and clears state back to initial seed."""
    state = SystemStateManager.get_instance()
    return state.reset_demo_state()
