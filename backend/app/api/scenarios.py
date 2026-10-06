"""
Scenario management and benchmark execution endpoints.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import ScenarioRunRecord
from backend.app.schemas import (
    ScenarioDefinition,
    ScenarioRunRequest,
    ScenarioRunResponse,
    ScenarioRunDetail,
)
from backend.app.services.system_state import SystemStateManager

router = APIRouter()
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCENARIOS_DIR = REPO_ROOT / "data" / "scenarios"


@router.get("/scenarios", response_model=List[ScenarioDefinition])
def list_scenario_definitions():
    """Lists all available scenario definitions."""
    definitions = []
    for file_path in sorted(SCENARIOS_DIR.glob("*.json")):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            definitions.append(ScenarioDefinition(
                id=data.get("id", file_path.stem),
                name=data.get("name", file_path.stem),
                description=data.get("description", ""),
                duration_windows=int(data.get("duration_windows", 20)),
                processes_count=len(data.get("processes", [])),
                family=data.get("family", "benign"),
                expected_outcome=data.get("expected_outcome", "normal_exit"),
            ))
        except Exception:
            continue
    return definitions


@router.post("/scenarios/run", response_model=ScenarioRunResponse)
def run_scenario(payload: ScenarioRunRequest):
    """Starts running a scenario simulation in the background."""
    state = SystemStateManager.get_instance()
    try:
        run_id = state.start_scenario(
            scenario_name=payload.scenario_name,
            detector=payload.detector,
            policy=payload.policy,
            speed=payload.speed or 1.0,
            seed=payload.seed or 42,
        )
        return ScenarioRunResponse(
            run_id=run_id,
            scenario_name=payload.scenario_name,
            detector=payload.detector or state.pipeline.model_name,
            policy=payload.policy or state.policy,
            speed=payload.speed or 1.0,
            seed=payload.seed or 42,
            status="running",
            message=f"Scenario '{payload.scenario_name}' started successfully",
            simulated=True,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to start scenario: {e}")


@router.post("/scenarios/stop")
def stop_active_scenario():
    """Stops the currently running scenario."""
    state = SystemStateManager.get_instance()
    stopped = state.stop_scenario()
    if stopped:
        return {"success": True, "message": "Scenario stop signal sent", "simulated": True}
    return {"success": False, "message": "No running scenario to stop", "simulated": True}


@router.get("/scenarios/runs", response_model=List[ScenarioRunDetail])
def list_scenario_runs(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Lists historical and active scenario runs."""
    records = db.query(ScenarioRunRecord).order_by(ScenarioRunRecord.started_at.desc()).offset(offset).limit(limit).all()
    results = []
    for r in records:
        try:
            contained = json.loads(r.contained_pids)
        except Exception:
            contained = []

        try:
            summary = json.loads(r.summary_json)
        except Exception:
            summary = {}

        results.append(ScenarioRunDetail(
            id=r.id,
            scenario_name=r.scenario_name,
            detector=r.detector,
            policy=r.policy,
            speed=r.speed,
            seed=r.seed,
            status=r.status,
            started_at=r.started_at.isoformat(),
            completed_at=r.completed_at.isoformat() if r.completed_at else None,
            total_windows=r.total_windows,
            distinct_pids=r.distinct_pids,
            contained_pids=contained,
            time_to_detect_windows=r.time_to_detect_windows,
            time_to_detect_seconds=r.time_to_detect_seconds,
            wall_time_seconds=r.wall_time_seconds,
            files_encrypted=r.files_encrypted,
            files_restored=r.files_restored,
            files_intact=r.files_intact,
            panic_tripped=r.panic_tripped,
            summary=summary,
            simulated=True,
        ))
    return results


@router.get("/scenarios/runs/{run_id}", response_model=ScenarioRunDetail)
def get_scenario_run_detail(run_id: str, db: Session = Depends(get_db)):
    """Retrieves full metrics and timeline of a scenario run."""
    r = db.query(ScenarioRunRecord).filter(ScenarioRunRecord.id == run_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Scenario run not found")

    try:
        contained = json.loads(r.contained_pids)
    except Exception:
        contained = []

    try:
        summary = json.loads(r.summary_json)
    except Exception:
        summary = {}

    return ScenarioRunDetail(
        id=r.id,
        scenario_name=r.scenario_name,
        detector=r.detector,
        policy=r.policy,
        speed=r.speed,
        seed=r.seed,
        status=r.status,
        started_at=r.started_at.isoformat(),
        completed_at=r.completed_at.isoformat() if r.completed_at else None,
        total_windows=r.total_windows,
        distinct_pids=r.distinct_pids,
        contained_pids=contained,
        time_to_detect_windows=r.time_to_detect_windows,
        time_to_detect_seconds=r.time_to_detect_seconds,
        wall_time_seconds=r.wall_time_seconds,
        files_encrypted=r.files_encrypted,
        files_restored=r.files_restored,
        files_intact=r.files_intact,
        panic_tripped=r.panic_tripped,
        summary=summary,
        simulated=True,
    )


@router.get("/scenarios/filesystem")
def get_virtual_filesystem():
    """Returns the current state and file listing of the virtual filesystem."""
    state = SystemStateManager.get_instance()
    summary = state.response_engine.get_filesystem_summary()
    return {
        "summary": summary,
        "simulated": True,
    }


@router.post("/scenarios/reset")
def reset_scenario_state():
    """Resets virtual filesystem, active processes, and scorers to baseline."""
    state = SystemStateManager.get_instance()
    state.stop_scenario()
    with state._lock:
        state.active_processes.clear()
    state.response_engine = SimulatedResponse(default_policy=state.policy)
    state.pipeline.response_engine = state.response_engine
    state.pipeline.scorers.clear()
    state.safety_rails.reset_panic()
    return {
        "success": True,
        "message": "Scenario state and virtual filesystem reset to baseline",
        "simulated": True,
    }


@router.post("/scenarios/compare")
def compare_detectors(payload: dict):
    """
    Executes the same scenario across rule_based, random_forest, and xgboost
    sequentially with the exact same seed to generate side-by-side comparison.
    """
    scen_name = payload.get("scenario_name", "fast_ransomware")
    seed = int(payload.get("seed", 42))

    from backend.app.core.pipeline import DetectionPipeline
    from backend.app.core.sources import SimulatedSource
    from backend.app.core.response import SimulatedResponse
    from backend.app.core.safety import SafetyRails

    detectors = ["rule_based", "random_forest", "xgboost"]
    results = {}

    for det in detectors:
        engine = SimulatedResponse(default_policy="immediate")
        rails = SafetyRails()
        pipe = DetectionPipeline(
            response_engine=engine,
            safety_rails=rails,
            model_name=det,
            default_policy="immediate",
        )

        source = SimulatedSource(scenario=scen_name, seed=seed, speed=50.0)
        contained_pids = set()
        first_contain_w = None
        false_positives = 0
        total_w = 0

        for win in source.stream_all(sleep_delay=False):
            total_w += 1
            pid = int(win["pid"])
            label = str(win.get("label", "benign"))
            res = pipe.process_window(win)
            cont = res.get("containment")

            if cont and cont.get("action") == "freeze" and cont.get("is_frozen"):
                if label != "ransomware":
                    false_positives += 1
                if pid not in contained_pids:
                    contained_pids.add(pid)
                    if first_contain_w is None:
                        first_contain_w = win.get("window_idx")

        fs = engine.get_filesystem_summary()
        status_counts = fs.get("status_counts", {})
        restored = status_counts.get("restored", 0)
        encrypted = status_counts.get("encrypted", 0)
        intact = status_counts.get("healthy", 0)

        results[det] = {
            "detector": det,
            "total_windows": total_w,
            "time_to_detect_windows": first_contain_w,
            "time_to_detect_seconds": (first_contain_w * 2.0) if first_contain_w is not None else None,
            "contained_pids": sorted(list(contained_pids)),
            "files_lost": encrypted,
            "files_saved": intact + restored,
            "files_restored": restored,
            "false_alarms": false_positives,
        }

    return {
        "scenario": scen_name,
        "seed": seed,
        "comparison": results,
        "simulated": True,
    }

