"""
System status, health, and runtime control endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas import (
    HealthResponse,
    StatusResponse,
    ControlRequest,
    ControlResponse,
)
from backend.app.services.system_state import SystemStateManager

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def get_health():
    """Health check endpoint."""
    return HealthResponse(status="ok", version="0.1.0", simulated=True)


@router.get("/status", response_model=StatusResponse)
def get_status():
    """Returns active system status, detector, policy, and running scenario."""
    state = SystemStateManager.get_instance()
    running_scen = None
    if state.active_scenario and state.active_scenario.status == "running":
        running_scen = {
            "run_id": state.active_scenario.run_id,
            "scenario_name": state.active_scenario.scenario_name,
            "speed": state.active_scenario.speed,
            "seed": state.active_scenario.seed,
            "total_windows": state.active_scenario.total_windows,
        }

    return StatusResponse(
        status="running",
        mode=state.mode,
        active_policy=state.policy,
        active_detector=state.pipeline.model_name,
        active_manifest=state.pipeline.active_manifest,
        data_source=state.pipeline.active_manifest.get("data_source", "synthetic"),
        storm_panic=state.safety_rails.panic_tripped,
        running_scenario=running_scen,
        simulated=True,
    )


@router.post("/control", response_model=ControlResponse)
def set_control(payload: ControlRequest):
    """Updates runtime mode, response policy, active detector, or resets panic storm."""
    state = SystemStateManager.get_instance()
    messages = []

    if payload.mode:
        if payload.mode not in ("simulated", "live"):
            return ControlResponse(
                success=False,
                message=f"Invalid mode: {payload.mode}",
                mode=state.mode,
                policy=state.policy,
                active_detector=state.pipeline.model_name,
                storm_panic=state.safety_rails.panic_tripped,
                simulated=True,
            )
        state.mode = payload.mode
        messages.append(f"Mode set to {payload.mode}")

    if payload.policy:
        try:
            state.set_policy(payload.policy)
            messages.append(f"Policy set to {payload.policy}")
        except ValueError as e:
            return ControlResponse(
                success=False,
                message=str(e),
                mode=state.mode,
                policy=state.policy,
                active_detector=state.pipeline.model_name,
                storm_panic=state.safety_rails.panic_tripped,
                simulated=True,
            )

    if payload.detector:
        try:
            state.set_detector(payload.detector)
            messages.append(f"Detector switched to {payload.detector}")
        except Exception as e:
            return ControlResponse(
                success=False,
                message=f"Failed to switch detector: {e}",
                mode=state.mode,
                policy=state.policy,
                active_detector=state.pipeline.model_name,
                storm_panic=state.safety_rails.panic_tripped,
                simulated=True,
            )

    if payload.reset_storm:
        state.safety_rails.reset_storm_state()
        messages.append("Panic storm switch reset to normal")

    return ControlResponse(
        success=True,
        message="; ".join(messages) if messages else "No configuration changes requested",
        mode=state.mode,
        policy=state.policy,
        active_detector=state.pipeline.model_name,
        storm_panic=state.safety_rails.panic_tripped,
        simulated=True,
    )
