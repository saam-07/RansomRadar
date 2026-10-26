"""
Runtime state persistence and crash recovery for AdaptShield.
Persists contained PIDs and enables seamless recovery on agent restart,
including auto-resolve timeouts for manual operator decisions.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import AdaptShieldConfig
from .logging.logger import get_logger
from .response.containment_manager import (
    list_frozen_pids,
    request_manual_decision,
    resolve_manual_decision,
    unfreeze_pid,
)

logger = get_logger("adaptshield.state")


@dataclass
class ContainedProcessRecord:
    pid: int
    policy: str
    status: str  # "frozen", "awaiting_manual", "quarantined", "killed", "released"
    frozen_at: float
    evidence: dict[str, Any]
    quarantine_path: str | None = None
    overlay_upperdir: str | None = None
    overlay_workdir: str | None = None


class StateManager:
    def __init__(self, state_file: str | Path = "/var/lib/adaptshield/state.json"):
        self.state_file = Path(state_file)
        self.permission_denied = False
        self._ensure_dir()
        self.records: dict[int, ContainedProcessRecord] = {}
        self.load()

    def _ensure_dir(self):
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self.permission_denied = True
        except OSError:
            fallback_dir = Path("results/state")
            try:
                fallback_dir.mkdir(parents=True, exist_ok=True)
                self.state_file = fallback_dir / self.state_file.name
            except Exception:
                pass

    def load(self):
        """Loads state from the persistent state file."""
        try:
            if not self.state_file.exists():
                return
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            records = {}
            for pid_str, item in data.get("contained_pids", {}).items():
                pid = int(pid_str)
                records[pid] = ContainedProcessRecord(**item)
            self.records = records
            logger.info("Loaded runtime state with %d contained processes.", len(self.records))
        except PermissionError:
            self.permission_denied = True
            logger.warning("Permission denied reading state file %s.", self.state_file)
        except Exception as e:
            logger.warning("Could not read state file %s (%s); starting fresh.", self.state_file, e)

    def save(self):
        """Persists the current state atomically."""
        self._ensure_dir()
        tmp_file = self.state_file.with_suffix(".tmp")
        payload = {
            "version": "1.0.0",
            "updated_at": time.time(),
            "contained_pids": {str(k): asdict(v) for k, v in self.records.items()},
        }
        try:
            tmp_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(tmp_file, 0o640)
            except Exception:
                pass
            tmp_file.replace(self.state_file)
        except Exception as e:
            logger.error("Failed to save state to %s: %s", self.state_file, e)

    def record_containment(
        self,
        pid: int,
        policy: str,
        status: str,
        evidence: dict[str, Any],
        quarantine_path: str | None = None,
        overlay_upper: str | None = None,
        overlay_work: str | None = None,
    ):
        self.records[pid] = ContainedProcessRecord(
            pid=pid,
            policy=policy,
            status=status,
            frozen_at=time.time(),
            evidence=evidence,
            quarantine_path=quarantine_path,
            overlay_upperdir=overlay_upper,
            overlay_workdir=overlay_work,
        )
        self.save()

    def record_resolution(self, pid: int, decision: str):
        if pid in self.records:
            self.records[pid].status = "released" if decision == "release" else "confirmed_killed"
            self.save()

    def is_process_alive(self, pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            if sys.platform == "win32":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h:
                    kernel32.CloseHandle(h)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except (ProcessLookupError, PermissionError, OSError):
            return False

    def recover(self, config: AdaptShieldConfig) -> dict[str, Any]:
        """
        Recovers frozen and pending processes on agent startup.
        Handles auto-resolve timeouts for manual policy decisions.
        """
        recovered_actions: dict[int, str] = {}
        now = time.time()
        timeout = config.response.auto_resolve_after_seconds
        auto_action = config.response.auto_resolve_action

        # Also discover any frozen cgroups in filesystem not yet in state
        cgroup_pids = list_frozen_pids()
        for p in cgroup_pids:
            if p not in self.records:
                self.records[p] = ContainedProcessRecord(
                    pid=p,
                    policy="manual",
                    status="awaiting_manual",
                    frozen_at=now,
                    evidence={"recovered": True},
                )

        for pid, record in list(self.records.items()):
            if record.status not in ("frozen", "awaiting_manual"):
                continue

            alive = self.is_process_alive(pid)
            if not alive:
                logger.info("Recovered process PID=%d has terminated while offline. Cleaning up.", pid)
                unfreeze_pid(pid)
                record.status = "terminated_offline"
                recovered_actions[pid] = "cleaned_up_dead"
                continue

            if record.policy == "manual":
                elapsed = now - record.frozen_at
                if elapsed >= timeout:
                    logger.warning(
                        "[RECOVERY AUTO-RESOLVE] PID=%d manual decision timed out (%.1fs >= %.1fs). "
                        "Applying auto-resolve action: %s",
                        pid,
                        elapsed,
                        timeout,
                        auto_action,
                    )
                    if auto_action == "release":
                        unfreeze_pid(pid)
                        record.status = "auto_released"
                        recovered_actions[pid] = "auto_released"
                    elif auto_action == "confirm":
                        if record.overlay_upperdir and record.overlay_workdir:
                            resolve_manual_decision(
                                pid=pid,
                                decision="confirm",
                                upperdir=record.overlay_upperdir,
                                workdir=record.overlay_workdir,
                                quarantine_root=config.response.quarantine_dir,
                                control_dir=config.response.control_dir,
                            )
                        else:
                            unfreeze_pid(pid)
                        record.status = "auto_confirmed"
                        recovered_actions[pid] = "auto_confirmed"
                else:
                    logger.info(
                        "[RECOVERY] Resuming pending decision for PID=%d (elapsed: %.1fs, timeout: %.1fs)",
                        pid,
                        elapsed,
                        timeout,
                    )
                    request_manual_decision(config.response.control_dir, pid, record.evidence)
                    recovered_actions[pid] = "resumed_manual_pending"

            elif record.policy == "immediate":
                logger.info("[RECOVERY] Completing immediate containment for PID=%d", pid)
                unfreeze_pid(pid)
                record.status = "recovered_immediate"
                recovered_actions[pid] = "recovered_immediate"

        self.save()
        return {
            "recovered_count": len(recovered_actions),
            "actions": recovered_actions,
        }
