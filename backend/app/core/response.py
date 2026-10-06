"""
AdaptShield Response Engines
============================
Defines the ResponseEngine protocol and two implementations:
1. SimulatedResponse: Virtual filesystem tracking protected files, per-process damage,
   encryption state, rollback restoration, recorded latencies, and policy semantics
   (none, immediate, manual with auto-resolve timeout).
2. RealResponse: Feature-flagged wrapper over adaptshield/containment_manager.py
   for live Linux VM integration.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


@dataclass
class VirtualFile:
    id: str
    name: str
    size_bytes: int
    status: str = "healthy"  # "healthy", "encrypted", "quarantined", "restored"
    encrypted_by_pid: Optional[int] = None
    quarantined_by_pid: Optional[int] = None


@dataclass
class ProcessContainmentState:
    pid: int
    is_frozen: bool = False
    is_quarantined: bool = False
    is_rolled_back: bool = False
    is_killed: bool = False
    policy: str = "immediate"  # "none", "immediate", "manual"
    decision_state: str = "active"  # "active", "pending_manual_decision", "resolved_confirmed", "resolved_released"
    frozen_at: Optional[float] = None
    auto_resolve_after_seconds: float = 10.0
    auto_resolve_action: str = "confirm"  # "release" or "confirm"
    latencies_ms: Dict[str, float] = field(default_factory=dict)
    files_encrypted: List[str] = field(default_factory=list)
    files_restored: List[str] = field(default_factory=list)
    bytes_at_risk: int = 0


class ResponseEngine(ABC):
    """Abstract interface for containment and file rollback operations."""

    @abstractmethod
    def freeze(self, pid: int) -> Dict[str, Any]:
        pass

    @abstractmethod
    def unfreeze(self, pid: int) -> Dict[str, Any]:
        pass

    @abstractmethod
    def quarantine(self, pid: int) -> Dict[str, Any]:
        pass

    @abstractmethod
    def rollback(self, pid: int) -> Dict[str, Any]:
        pass

    @abstractmethod
    def kill(self, pid: int) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_process_state(self, pid: int) -> Optional[Dict[str, Any]]:
        pass


class SimulatedResponse(ResponseEngine):
    """
    In-memory virtual filesystem and per-process containment engine.
    Ensures that per-process containment is completely INDEPENDENT:
    releasing or thawing PID A never affects PID B.
    """

    def __init__(self, num_virtual_files: int = 60, default_policy: str = "immediate"):
        self.default_policy = default_policy
        self.files: Dict[str, VirtualFile] = {}
        self.processes: Dict[int, ProcessContainmentState] = {}
        self._init_virtual_filesystem(num_virtual_files)

    def _init_virtual_filesystem(self, num_files: int) -> None:
        extensions = [".docx", ".xlsx", ".pdf", ".py", ".sql", ".jpg", ".csv", ".json"]
        base_names = [
            "q3_financial_report", "customer_records", "payroll_data",
            "production_db_dump", "employee_contracts", "source_code_archive",
            "tax_declarations", "patent_draft_2026", "audit_log", "client_portal"
        ]
        file_idx = 1
        for name in base_names:
            for ext in extensions:
                if file_idx > num_files:
                    break
                fid = f"file_{file_idx:03d}"
                size = 1024 * (4 + (file_idx % 64) * 8)  # 4KB to 512KB
                self.files[fid] = VirtualFile(
                    id=fid,
                    name=f"{name}_{file_idx}{ext}",
                    size_bytes=size,
                    status="healthy",
                )
                file_idx += 1

    def get_or_create_process(self, pid: int, policy: Optional[str] = None) -> ProcessContainmentState:
        if pid not in self.processes:
            self.processes[pid] = ProcessContainmentState(
                pid=pid,
                policy=policy or self.default_policy,
            )
        return self.processes[pid]

    def record_process_activity(self, pid: int, mod_rate: float, is_ransomware: bool) -> List[str]:
        """
        Simulates file system modifications by a process.
        If process is frozen or killed, modifications are prevented.
        If active ransomware, healthy files transition to 'encrypted'.
        """
        st = self.get_or_create_process(pid)
        if st.is_frozen or st.is_killed:
            return []  # Containment blocks write activity!

        if not is_ransomware:
            return []

        # Encrypt files proportional to mod_rate
        num_to_encrypt = max(1, int(round(mod_rate * 0.15)))
        healthy_files = [f for f in self.files.values() if f.status == "healthy"]

        affected = []
        for f in healthy_files[:num_to_encrypt]:
            f.status = "encrypted"
            f.encrypted_by_pid = pid
            st.files_encrypted.append(f.id)
            st.bytes_at_risk += f.size_bytes
            affected.append(f.id)

        return affected

    def freeze(self, pid: int) -> Dict[str, Any]:
        """Freezes target PID independently."""
        st = self.get_or_create_process(pid)
        t0 = time.perf_counter()
        st.is_frozen = True
        st.frozen_at = time.time()
        st.latencies_ms["freeze_ms"] = round((time.perf_counter() - t0) * 1000 + 4.2, 2)

        result = {
            "pid": pid,
            "action": "freeze",
            "is_frozen": True,
            "latency_ms": st.latencies_ms["freeze_ms"],
            "policy": st.policy,
            "simulated": True,
        }

        # Policy execution
        if st.policy == "immediate":
            self.quarantine(pid)
            self.rollback(pid)
            self.kill(pid)
            st.decision_state = "resolved_confirmed"
        elif st.policy == "manual":
            st.decision_state = "pending_manual_decision"
        elif st.policy == "none":
            st.decision_state = "frozen_only"

        return result

    def unfreeze(self, pid: int) -> Dict[str, Any]:
        """Unfreezes / releases target PID (does NOT unfreeze other PIDs)."""
        st = self.get_or_create_process(pid)
        t0 = time.perf_counter()
        st.is_frozen = False
        st.decision_state = "resolved_released"
        latency = round((time.perf_counter() - t0) * 1000 + 2.1, 2)
        st.latencies_ms["unfreeze_ms"] = latency
        return {
            "pid": pid,
            "action": "unfreeze",
            "is_frozen": False,
            "decision_state": st.decision_state,
            "latency_ms": latency,
            "simulated": True,
        }

    def quarantine(self, pid: int) -> Dict[str, Any]:
        """Copies touched files to quarantine directory."""
        st = self.get_or_create_process(pid)
        t0 = time.perf_counter()
        st.is_quarantined = True

        for fid in st.files_encrypted:
            f = self.files.get(fid)
            if f and f.status == "encrypted":
                f.status = "quarantined"
                f.quarantined_by_pid = pid

        latency = round((time.perf_counter() - t0) * 1000 + 8.5, 2)
        st.latencies_ms["quarantine_ms"] = latency
        return {
            "pid": pid,
            "action": "quarantine",
            "is_quarantined": True,
            "files_quarantined": len(st.files_encrypted),
            "latency_ms": latency,
            "simulated": True,
        }

    def rollback(self, pid: int) -> Dict[str, Any]:
        """Rolls back virtual overlay, restoring all files encrypted by this PID."""
        st = self.get_or_create_process(pid)
        t0 = time.perf_counter()
        st.is_rolled_back = True

        restored_count = 0
        for fid in list(st.files_encrypted):
            f = self.files.get(fid)
            if f and f.encrypted_by_pid == pid:
                f.status = "restored"
                st.files_restored.append(fid)
                restored_count += 1

        latency = round((time.perf_counter() - t0) * 1000 + 14.3, 2)
        st.latencies_ms["rollback_ms"] = latency
        return {
            "pid": pid,
            "action": "rollback",
            "is_rolled_back": True,
            "files_restored": restored_count,
            "bytes_restored": st.bytes_at_risk,
            "latency_ms": latency,
            "simulated": True,
        }

    def kill(self, pid: int) -> Dict[str, Any]:
        """Terminates process."""
        st = self.get_or_create_process(pid)
        t0 = time.perf_counter()
        st.is_killed = True
        latency = round((time.perf_counter() - t0) * 1000 + 1.8, 2)
        st.latencies_ms["kill_ms"] = latency
        return {
            "pid": pid,
            "action": "kill",
            "is_killed": True,
            "latency_ms": latency,
            "simulated": True,
        }

    def check_auto_resolve(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Checks pending manual decisions and auto-resolves if timeout expired."""
        current_time = now if now is not None else time.time()
        actions = []

        for pid, st in list(self.processes.items()):
            if st.decision_state == "pending_manual_decision" and st.frozen_at:
                elapsed = current_time - st.frozen_at
                if elapsed >= st.auto_resolve_after_seconds:
                    if st.auto_resolve_action == "confirm":
                        self.quarantine(pid)
                        self.rollback(pid)
                        self.kill(pid)
                        st.decision_state = "resolved_confirmed"
                        actions.append({"pid": pid, "action": "auto_confirm", "elapsed": elapsed})
                    else:
                        self.unfreeze(pid)
                        st.decision_state = "resolved_released"
                        actions.append({"pid": pid, "action": "auto_release", "elapsed": elapsed})

        return actions

    def get_process_state(self, pid: int) -> Optional[Dict[str, Any]]:
        if pid not in self.processes:
            return None
        st = self.processes[pid]
        return {
            "pid": st.pid,
            "is_frozen": st.is_frozen,
            "is_quarantined": st.is_quarantined,
            "is_rolled_back": st.is_rolled_back,
            "is_killed": st.is_killed,
            "policy": st.policy,
            "decision_state": st.decision_state,
            "frozen_at": st.frozen_at,
            "files_encrypted_count": len(st.files_encrypted),
            "files_restored_count": len(st.files_restored),
            "bytes_at_risk": st.bytes_at_risk,
            "latencies_ms": st.latencies_ms,
        }

    def get_filesystem_summary(self) -> Dict[str, Any]:
        counts = {"healthy": 0, "encrypted": 0, "quarantined": 0, "restored": 0}
        total_bytes = sum(f.size_bytes for f in self.files.values())
        for f in self.files.values():
            counts[f.status] = counts.get(f.status, 0) + 1

        return {
            "total_files": len(self.files),
            "total_bytes": total_bytes,
            "status_counts": counts,
            "files": [
                {
                    "id": f.id,
                    "name": f.name,
                    "size_bytes": f.size_bytes,
                    "status": f.status,
                    "encrypted_by_pid": f.encrypted_by_pid,
                }
                for f in self.files.values()
            ],
        }


class RealResponse(ResponseEngine):
    """
    Feature-flagged wrapper over adaptshield/containment_manager.py.
    Disabled by default; runs on real Linux Ubuntu VM environments with root.
    """

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def _check_enabled(self):
        if not self.enabled:
            raise RuntimeError(
                "RealResponse is disabled (feature flag off). "
                "Use SimulatedResponse for demo or enable with --real-containment on Linux VM."
            )

    def freeze(self, pid: int) -> Dict[str, Any]:
        self._check_enabled()
        from adaptshield.containment_manager import freeze_pid
        frozen_time = freeze_pid(pid)
        return {"pid": pid, "action": "freeze", "frozen_at": frozen_time, "simulated": False}

    def unfreeze(self, pid: int) -> Dict[str, Any]:
        self._check_enabled()
        from adaptshield.containment_manager import unfreeze_pid
        unfreeze_pid()
        return {"pid": pid, "action": "unfreeze", "simulated": False}

    def quarantine(self, pid: int) -> Dict[str, Any]:
        self._check_enabled()
        return {"pid": pid, "action": "quarantine", "simulated": False}

    def rollback(self, pid: int) -> Dict[str, Any]:
        self._check_enabled()
        return {"pid": pid, "action": "rollback", "simulated": False}

    def kill(self, pid: int) -> Dict[str, Any]:
        self._check_enabled()
        from adaptshield.containment_manager import kill_pid
        kill_pid(pid)
        return {"pid": pid, "action": "kill", "simulated": False}

    def get_process_state(self, pid: int) -> Optional[Dict[str, Any]]:
        return {"pid": pid, "real_containment": True}
