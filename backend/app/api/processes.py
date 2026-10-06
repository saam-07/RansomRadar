"""
Process inspection and status endpoints.
"""

from __future__ import annotations

from typing import List
from fastapi import APIRouter

from backend.app.schemas import ProcessItem, ProcessListResponse
from backend.app.services.system_state import SystemStateManager

router = APIRouter()


@router.get("/processes", response_model=ProcessListResponse)
def list_processes():
    """Lists all monitored and active processes in the pipeline."""
    state = SystemStateManager.get_instance()
    with state._lock:
        items = []
        for pid, pdata in state.active_processes.items():
            items.append(ProcessItem(
                pid=pid,
                process_name=pdata.get("process_name", f"proc_{pid}"),
                cmdline=pdata.get("cmdline", f"/usr/bin/{pdata.get('process_name', f'proc_{pid}')}"),
                label=pdata.get("label", "benign"),
                risk_level=pdata.get("risk_level", "NORMAL"),
                ewma=float(pdata.get("ewma", 0.0)),
                probability=float(pdata.get("probability", 0.0)),
                status=pdata.get("status", "normal"),
                is_frozen=bool(pdata.get("is_frozen", False)),
                is_quarantined=bool(pdata.get("is_quarantined", False)),
                files_touched=int(pdata.get("files_touched", 0)),
                files_encrypted=int(pdata.get("files_encrypted", 0)),
                last_window_idx=int(pdata.get("last_window_idx", 0)),
                updated_at=pdata.get("updated_at"),
                simulated=True,
            ))

    # Sort by risk EWMA descending
    items.sort(key=lambda x: x.ewma, reverse=True)
    return ProcessListResponse(processes=items, total=len(items), simulated=True)
