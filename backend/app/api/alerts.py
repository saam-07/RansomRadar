"""
Alerts and Containment action endpoints.
Includes forensic evidence (SHAP/tree explanation, feature row, files touched).
"""

from __future__ import annotations

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import AlertRecord, ContainmentRecord
from backend.app.schemas import (
    AlertItem,
    AlertListResponse,
    ContainmentActionRequest,
    ContainmentActionResponse,
)
from backend.app.services.system_state import SystemStateManager

router = APIRouter()


@router.get("/alerts", response_model=AlertListResponse)
def list_alerts(
    run_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Lists alerts with evidence, filterable by run_id, risk_level, status."""
    query = db.query(AlertRecord)
    if run_id:
        query = query.filter(AlertRecord.run_id == run_id)
    if risk_level:
        query = query.filter(AlertRecord.risk_level == risk_level)
    if status:
        query = query.filter(AlertRecord.status == status)

    total = query.count()
    records = query.order_by(AlertRecord.timestamp.desc()).offset(offset).limit(limit).all()

    items = []
    for r in records:
        try:
            explanation = json.loads(r.explanation_json)
        except Exception:
            explanation = {}

        try:
            wdata = json.loads(r.window_data_json)
        except Exception:
            wdata = {}

        items.append(AlertItem(
            id=r.id,
            run_id=r.run_id,
            timestamp=r.timestamp.isoformat(),
            pid=r.pid,
            process_name=r.process_name,
            risk_level=r.risk_level,
            ewma_score=r.ewma_score,
            model_name=r.model_name,
            explanation=explanation,
            window_data=wdata,
            status=r.status,
            action_taken=r.action_taken,
            simulated=True,
        ))

    return AlertListResponse(alerts=items, total=total, simulated=True)


@router.get("/alerts/{alert_id}", response_model=AlertItem)
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    """Retrieves full forensic evidence for a specific alert."""
    record = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Alert not found")

    try:
        explanation = json.loads(record.explanation_json)
    except Exception:
        explanation = {}

    try:
        wdata = json.loads(record.window_data_json)
    except Exception:
        wdata = {}

    return AlertItem(
        id=record.id,
        run_id=record.run_id,
        timestamp=record.timestamp.isoformat(),
        pid=record.pid,
        process_name=record.process_name,
        risk_level=record.risk_level,
        ewma_score=record.ewma_score,
        model_name=record.model_name,
        explanation=explanation,
        window_data=wdata,
        status=record.status,
        action_taken=record.action_taken,
        simulated=True,
    )


@router.post("/containment/release", response_model=ContainmentActionResponse)
def release_process_containment(payload: ContainmentActionRequest, db: Session = Depends(get_db)):
    """Operator overrides containment by releasing / unfreezing a process."""
    state = SystemStateManager.get_instance()
    try:
        res = state.release_process(payload.pid, reason=payload.reason or "Operator release")
        # Update alert status in DB if any active alert exists for this PID
        active_alert = db.query(AlertRecord).filter(
            AlertRecord.pid == payload.pid,
            AlertRecord.status == "active",
        ).first()
        if active_alert:
            active_alert.status = "released"
            db.commit()

        return ContainmentActionResponse(
            pid=payload.pid,
            action="release",
            success=True,
            status="released",
            message=f"Process {payload.pid} successfully unfreezed",
            simulated=True,
        )
    except Exception as e:
        return ContainmentActionResponse(
            pid=payload.pid,
            action="release",
            success=False,
            status="error",
            message=str(e),
            simulated=True,
        )


@router.post("/containment/confirm", response_model=ContainmentActionResponse)
def confirm_process_containment(payload: ContainmentActionRequest, db: Session = Depends(get_db)):
    """Operator confirms threat and terminates/kills process."""
    state = SystemStateManager.get_instance()
    try:
        res = state.confirm_process(payload.pid, reason=payload.reason or "Operator confirmed threat")
        # Update alert status in DB
        active_alert = db.query(AlertRecord).filter(
            AlertRecord.pid == payload.pid,
            AlertRecord.status == "active",
        ).first()
        if active_alert:
            active_alert.status = "confirmed"
            db.commit()

        return ContainmentActionResponse(
            pid=payload.pid,
            action="confirm",
            success=True,
            status="confirmed",
            message=f"Threat confirmed for PID {payload.pid}; process killed",
            simulated=True,
        )
    except Exception as e:
        return ContainmentActionResponse(
            pid=payload.pid,
            action="confirm",
            success=False,
            status="error",
            message=str(e),
            simulated=True,
        )
