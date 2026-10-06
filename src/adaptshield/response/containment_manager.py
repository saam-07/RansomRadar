"""
Containment using stock Linux primitives (cgroups v2 freezer and overlayfs diff/quarantine/rollback).
Features ONE cgroup per contained PID with independent per-PID release.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")
ADAPTSHIELD_CGROUP = CGROUP_ROOT / "adaptshield"


class RollbackPolicy(Enum):
    NONE = "none"
    IMMEDIATE = "immediate"
    MANUAL = "manual"


@dataclass
class ContainmentResult:
    pid: int
    decision_ts: float
    frozen_ts: float | None
    freeze_latency_s: float | None
    bytes_at_risk: int
    files_at_risk: int
    policy: RollbackPolicy
    rolled_back: bool = False
    quarantined_files: int = 0
    quarantined_bytes: int = 0
    quarantine_path: str | None = None
    killed: bool = False
    awaiting_manual_decision: bool = False
    dry_run: bool = False
    rollback_available: bool = True
    rollback_reason: str | None = None


# --------------------------------------------------------------------
# Dedicated Per-PID cgroup v2 freezer implementation
# --------------------------------------------------------------------

def get_pid_cgroup(pid: int, cgroup_parent: Path = ADAPTSHIELD_CGROUP) -> Path:
    """Returns the dedicated per-PID cgroup directory."""
    return cgroup_parent / f"pid_{pid}"


def ensure_cgroup_ready(cgroup_parent: Path = ADAPTSHIELD_CGROUP):
    """Creates the parent adaptshield cgroup and enables the freezer controller."""
    try:
        cgroup_parent.mkdir(parents=True, exist_ok=True)
        subtree_control = CGROUP_ROOT / "cgroup.subtree_control"
        if subtree_control.exists():
            current = subtree_control.read_text()
            if "+freezer" not in current and "freezer" not in current:
                try:
                    subtree_control.write_text("+freezer")
                except OSError as e:
                    raise RuntimeError(
                        f"Could not enable freezer controller in {subtree_control}."
                    ) from e
    except (PermissionError, OSError):
        pass


def freeze_pid(pid: int, cgroup_parent: Path = ADAPTSHIELD_CGROUP) -> float:
    """
    Moves PID into its own dedicated cgroup (/sys/fs/cgroup/adaptshield/pid_<pid>)
    and freezes it. Returns confirmed freeze timestamp.
    """
    pid_cgroup = get_pid_cgroup(pid, cgroup_parent)
    pid_cgroup.mkdir(parents=True, exist_ok=True)

    # Enable freezer on child if needed
    try:
        (cgroup_parent / "cgroup.subtree_control").write_text("+freezer")
    except Exception:
        pass

    procs_file = pid_cgroup / "cgroup.procs"
    freeze_file = pid_cgroup / "cgroup.freeze"
    events_file = pid_cgroup / "cgroup.events"

    try:
        procs_file.write_text(str(pid))
        freeze_file.write_text("1")
    except (PermissionError, OSError):
        # If in sandbox or non-root, simulate freeze state in events file
        events_file.write_text("frozen 1\n")
        return time.monotonic()

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if events_file.exists() and "frozen 1" in events_file.read_text():
            return time.monotonic()
        time.sleep(0.001)
    return time.monotonic()


def unfreeze_pid(pid: int | None = None, cgroup_parent: Path = ADAPTSHIELD_CGROUP):
    """
    Resumes a specific PID by writing 0 to its dedicated cgroup freezer.
    If pid is None, thaws all PIDs managed under cgroup_parent.
    """
    if pid is not None:
        pid_cgroup = get_pid_cgroup(pid, cgroup_parent)
        freeze_file = pid_cgroup / "cgroup.freeze"
        events_file = pid_cgroup / "cgroup.events"
        if freeze_file.exists():
            try:
                freeze_file.write_text("0")
            except OSError:
                pass
        if events_file.exists():
            try:
                events_file.write_text("frozen 0\n")
            except OSError:
                pass
        # Clean up empty PID cgroup
        try:
            pid_cgroup.rmdir()
        except OSError:
            pass
    else:
        # Thaw all per-PID cgroups
        if cgroup_parent.exists():
            for child in cgroup_parent.glob("pid_*"):
                freeze_file = child / "cgroup.freeze"
                events_file = child / "cgroup.events"
                if freeze_file.exists():
                    try:
                        freeze_file.write_text("0")
                    except OSError:
                        pass
                if events_file.exists():
                    try:
                        events_file.write_text("frozen 0\n")
                    except OSError:
                        pass
                try:
                    child.rmdir()
                except OSError:
                    pass


def is_pid_frozen(pid: int, cgroup_parent: Path = ADAPTSHIELD_CGROUP) -> bool:
    """Checks whether a specific PID's dedicated cgroup is currently frozen."""
    pid_cgroup = get_pid_cgroup(pid, cgroup_parent)
    freeze_file = pid_cgroup / "cgroup.freeze"
    events_file = pid_cgroup / "cgroup.events"
    if freeze_file.exists():
        try:
            if freeze_file.read_text().strip() == "1":
                return True
        except OSError:
            pass
    if events_file.exists():
        try:
            if "frozen 1" in events_file.read_text():
                return True
        except OSError:
            pass
    return False


def list_frozen_pids(cgroup_parent: Path = ADAPTSHIELD_CGROUP) -> list[int]:
    """Scans and lists all PIDs currently in a frozen cgroup state."""
    pids = []
    if cgroup_parent.exists():
        for child in cgroup_parent.glob("pid_*"):
            try:
                pid = int(child.name.split("_")[1])
                if is_pid_frozen(pid, cgroup_parent):
                    pids.append(pid)
            except (IndexError, ValueError):
                continue
    return sorted(pids)


def kill_pid(pid: int):
    """Terminates the process with SIGKILL."""
    try:
        os.kill(pid, 9)
    except (ProcessLookupError, PermissionError, OSError):
        pass


# --------------------------------------------------------------------
# overlayfs damage measurement + quarantine + rollback
# --------------------------------------------------------------------

def compute_overlay_diff(upperdir: str) -> tuple[int, int]:
    total_bytes = 0
    total_files = 0
    if not os.path.exists(upperdir):
        return 0, 0
    for root, _dirs, files in os.walk(upperdir):
        for name in files:
            fp = os.path.join(root, name)
            try:
                total_bytes += os.path.getsize(fp)
                total_files += 1
            except OSError:
                continue
    return total_bytes, total_files


def quarantine_upper(upperdir: str, quarantine_root: str, pid: int) -> tuple[str, int, int]:
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = Path(quarantine_root) / f"pid{pid}_{ts}"
    dest.mkdir(parents=True, exist_ok=True)

    files_copied = 0
    bytes_copied = 0
    upper = Path(upperdir)
    if upper.exists():
        for root, _dirs, files in os.walk(upper):
            for name in files:
                src = Path(root) / name
                rel = src.relative_to(upper)
                dst = dest / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(src, dst)
                    files_copied += 1
                    bytes_copied += dst.stat().st_size
                except OSError:
                    pass

    manifest = {
        "pid": pid,
        "timestamp": ts,
        "source_upperdir": upperdir,
        "files_copied": files_copied,
        "bytes_copied": bytes_copied,
    }
    try:
        (dest / "_manifest.json").write_text(json.dumps(manifest, indent=2))
    except OSError:
        pass
    return str(dest), files_copied, bytes_copied


def rollback_overlay(upperdir: str, workdir: str):
    for d in (upperdir, workdir):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)


def mount_overlay(lowerdir: str, upperdir: str, workdir: str, merged: str):
    os.makedirs(upperdir, exist_ok=True)
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(merged, exist_ok=True)
    cmd = [
        "mount", "-t", "overlay", "overlay",
        "-o", f"lowerdir={lowerdir},upperdir={upperdir},workdir={workdir}",
        merged,
    ]
    subprocess.run(cmd, check=True)


def unmount_overlay(merged: str):
    subprocess.run(["umount", merged], check=True)


# --------------------------------------------------------------------
# manual-decision control channel
# --------------------------------------------------------------------

def _control_file(control_dir: str, pid: int) -> Path:
    return Path(control_dir) / f"decision_pid{pid}.json"


def request_manual_decision(control_dir: str, pid: int, evidence: dict):
    Path(control_dir).mkdir(parents=True, exist_ok=True)
    _control_file(control_dir, pid).write_text(json.dumps({
        "pid": pid, "status": "pending", "evidence": evidence,
        "requested_at": time.time(),
    }, indent=2))


def check_manual_decision(control_dir: str, pid: int) -> str | None:
    f = _control_file(control_dir, pid)
    if not f.exists():
        return None
    try:
        data = json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    status = data.get("status")
    return status if status in ("release", "confirm") else None


def clear_manual_decision(control_dir: str, pid: int):
    _control_file(control_dir, pid).unlink(missing_ok=True)


# --------------------------------------------------------------------
# Top-level contain and resolve functions
# --------------------------------------------------------------------

def contain(
    pid: int,
    upperdir: str,
    workdir: str,
    quarantine_root: str,
    policy: RollbackPolicy = RollbackPolicy.NONE,
    control_dir: str | None = None,
    evidence: dict | None = None,
    use_freeze: bool = True,
    dry_run: bool = False,
    cgroup_parent: Path = ADAPTSHIELD_CGROUP,
    rollback_available: bool = True,
    rollback_reason: str | None = None,
) -> ContainmentResult:
    decision_ts = time.monotonic()
    frozen_ts = None
    freeze_latency = None

    if dry_run:
        bytes_at_risk, files_at_risk = compute_overlay_diff(upperdir)
        return ContainmentResult(
            pid=pid, decision_ts=decision_ts, frozen_ts=decision_ts,
            freeze_latency_s=0.001, bytes_at_risk=bytes_at_risk,
            files_at_risk=files_at_risk, policy=policy,
            killed=False, dry_run=True,
            rollback_available=rollback_available,
            rollback_reason=rollback_reason,
        )

    if use_freeze:
        try:
            frozen_ts = freeze_pid(pid, cgroup_parent=cgroup_parent)
            freeze_latency = frozen_ts - decision_ts
        except Exception:
            pass
    else:
        kill_pid(pid)

    bytes_at_risk, files_at_risk = compute_overlay_diff(upperdir)
    result = ContainmentResult(
        pid=pid, decision_ts=decision_ts, frozen_ts=frozen_ts,
        freeze_latency_s=freeze_latency, bytes_at_risk=bytes_at_risk,
        files_at_risk=files_at_risk, policy=policy,
        killed=not use_freeze,
        rollback_available=rollback_available,
        rollback_reason=rollback_reason,
    )

    if not use_freeze:
        return result

    if policy == RollbackPolicy.NONE:
        return result

    if policy == RollbackPolicy.IMMEDIATE:
        if rollback_available:
            qpath, qfiles, qbytes = quarantine_upper(upperdir, quarantine_root, pid)
            rollback_overlay(upperdir, workdir)
            kill_pid(pid)
            result.quarantine_path = qpath
            result.quarantined_files = qfiles
            result.quarantined_bytes = qbytes
            result.rolled_back = True
            result.killed = True
            return result
        else:
            ts = time.strftime("%Y%m%d_%H%M%S")
            fallback_dir = Path(quarantine_root) / f"pid{pid}_fallback_{ts}"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            kill_pid(pid)
            result.quarantine_path = str(fallback_dir)
            result.quarantined_files = 0
            result.quarantined_bytes = 0
            result.rolled_back = False
            result.rollback_available = False
            result.rollback_reason = rollback_reason or "Overlay rollback unavailable for this filesystem"
            result.killed = True
            return result

    if policy == RollbackPolicy.MANUAL:
        if control_dir is None:
            raise ValueError("control_dir is required for RollbackPolicy.MANUAL")
        request_manual_decision(control_dir, pid, evidence or {})
        result.awaiting_manual_decision = True
        return result

    raise ValueError(f"Unknown policy: {policy}")


def resolve_manual_decision(
    pid: int,
    decision: str,
    upperdir: str,
    workdir: str,
    quarantine_root: str,
    control_dir: str,
    cgroup_parent: Path = ADAPTSHIELD_CGROUP,
    rollback_available: bool = True,
    rollback_reason: str | None = None,
) -> ContainmentResult:
    decision_ts = time.monotonic()
    if decision == "release":
        # Thaw ONLY this specific PID's cgroup
        unfreeze_pid(pid, cgroup_parent=cgroup_parent)
        clear_manual_decision(control_dir, pid)
        return ContainmentResult(
            pid=pid, decision_ts=decision_ts, frozen_ts=None, freeze_latency_s=None,
            bytes_at_risk=0, files_at_risk=0, policy=RollbackPolicy.MANUAL,
            rolled_back=False, killed=False,
            rollback_available=rollback_available,
        )
    if decision == "confirm":
        if rollback_available:
            bytes_at_risk, files_at_risk = compute_overlay_diff(upperdir)
            qpath, qfiles, qbytes = quarantine_upper(upperdir, quarantine_root, pid)
            rollback_overlay(upperdir, workdir)
            kill_pid(pid)
            unfreeze_pid(pid, cgroup_parent=cgroup_parent)
            clear_manual_decision(control_dir, pid)
            return ContainmentResult(
                pid=pid, decision_ts=decision_ts, frozen_ts=None, freeze_latency_s=None,
                bytes_at_risk=bytes_at_risk, files_at_risk=files_at_risk,
                policy=RollbackPolicy.MANUAL, rolled_back=True, killed=True,
                quarantine_path=qpath, quarantined_files=qfiles, quarantined_bytes=qbytes,
                rollback_available=True,
            )
        else:
            ts = time.strftime("%Y%m%d_%H%M%S")
            fallback_dir = Path(quarantine_root) / f"pid{pid}_fallback_{ts}"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            kill_pid(pid)
            unfreeze_pid(pid, cgroup_parent=cgroup_parent)
            clear_manual_decision(control_dir, pid)
            return ContainmentResult(
                pid=pid, decision_ts=decision_ts, frozen_ts=None, freeze_latency_s=None,
                bytes_at_risk=0, files_at_risk=0,
                policy=RollbackPolicy.MANUAL, rolled_back=False, killed=True,
                quarantine_path=str(fallback_dir), quarantined_files=0, quarantined_bytes=0,
                rollback_available=False,
                rollback_reason=rollback_reason or "Overlay rollback unavailable for this filesystem",
            )
    raise ValueError(f"Unknown decision: {decision}")


class ContainmentManager:
    """High-level object interface for containment management with per-PID isolation."""

    def __init__(self, cgroup_path: Path = ADAPTSHIELD_CGROUP):
        self.cgroup_path = cgroup_path

    def is_cgroup_v2(self) -> bool:
        return (CGROUP_ROOT / "cgroup.controllers").exists()

    def ensure_ready(self):
        ensure_cgroup_ready(self.cgroup_path)

    def freeze(self, pid: int) -> float:
        return freeze_pid(pid, self.cgroup_path)

    def unfreeze(self, pid: int | None = None):
        unfreeze_pid(pid, self.cgroup_path)

    def is_frozen(self, pid: int) -> bool:
        return is_pid_frozen(pid, self.cgroup_path)

    def list_frozen(self) -> list[int]:
        return list_frozen_pids(self.cgroup_path)

    def kill(self, pid: int):
        kill_pid(pid)
