"""
Containment using stock Linux primitives (cgroups v2 freezer and overlayfs diff/quarantine/rollback).
"""
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


class ContainmentManager:
    """Manages cgroup v2 freezer and filesystem containment policies."""

    def __init__(self, cgroup_path: Path = ADAPTSHIELD_CGROUP):
        self.cgroup_path = cgroup_path

    def is_cgroup_v2(self) -> bool:
        return (CGROUP_ROOT / "cgroup.controllers").exists()

    def ensure_ready(self):
        ensure_cgroup_ready()

    def freeze(self, pid: int) -> float:
        return freeze_pid(pid)

    def unfreeze(self):
        unfreeze_pid()

    def kill(self, pid: int):
        kill_pid(pid)


def ensure_cgroup_ready():
    """Create the adaptshield cgroup and enable the freezer controller."""
    try:
        ADAPTSHIELD_CGROUP.mkdir(exist_ok=True)
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


def freeze_pid(pid: int) -> float:
    """Move PID into the AdaptShield cgroup and freeze it."""
    procs_file = ADAPTSHIELD_CGROUP / "cgroup.procs"
    procs_file.write_text(str(pid))
    freeze_file = ADAPTSHIELD_CGROUP / "cgroup.freeze"
    freeze_file.write_text("1")
    events_file = ADAPTSHIELD_CGROUP / "cgroup.events"
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if "frozen 1" in events_file.read_text():
            return time.monotonic()
        time.sleep(0.001)
    raise TimeoutError(f"PID {pid} did not report frozen within 2s")


def unfreeze_pid():
    """Resume processes in the AdaptShield cgroup."""
    freeze_file = ADAPTSHIELD_CGROUP / "cgroup.freeze"
    if freeze_file.exists():
        freeze_file.write_text("0")


def kill_pid(pid: int):
    """Terminates the process."""
    try:
        os.kill(pid, 9)
    except (ProcessLookupError, PermissionError):
        pass


def compute_overlay_diff(upperdir: str) -> tuple[int, int]:
    """Returns (bytes_at_risk, files_at_risk) by walking overlayfs upperdir."""
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


def contain(pid: int, upperdir: str, workdir: str, quarantine_root: str,
            policy: RollbackPolicy = RollbackPolicy.NONE,
            control_dir: str | None = None,
            evidence: dict | None = None,
            use_freeze: bool = True) -> ContainmentResult:
    decision_ts = time.monotonic()
    frozen_ts = None
    freeze_latency = None

    if use_freeze:
        try:
            frozen_ts = freeze_pid(pid)
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
    )

    if not use_freeze:
        return result

    if policy == RollbackPolicy.NONE:
        return result

    if policy == RollbackPolicy.IMMEDIATE:
        qpath, qfiles, qbytes = quarantine_upper(upperdir, quarantine_root, pid)
        rollback_overlay(upperdir, workdir)
        kill_pid(pid)
        result.quarantine_path = qpath
        result.quarantined_files = qfiles
        result.quarantined_bytes = qbytes
        result.rolled_back = True
        result.killed = True
        return result

    if policy == RollbackPolicy.MANUAL:
        if control_dir is None:
            raise ValueError("control_dir is required for RollbackPolicy.MANUAL")
        request_manual_decision(control_dir, pid, evidence or {})
        result.awaiting_manual_decision = True
        return result

    raise ValueError(f"Unknown policy: {policy}")


def resolve_manual_decision(pid: int, decision: str, upperdir: str, workdir: str,
                             quarantine_root: str, control_dir: str) -> ContainmentResult:
    decision_ts = time.monotonic()
    if decision == "release":
        unfreeze_pid()
        clear_manual_decision(control_dir, pid)
        return ContainmentResult(
            pid=pid, decision_ts=decision_ts, frozen_ts=None, freeze_latency_s=None,
            bytes_at_risk=0, files_at_risk=0, policy=RollbackPolicy.MANUAL,
            rolled_back=False, killed=False,
        )
    if decision == "confirm":
        bytes_at_risk, files_at_risk = compute_overlay_diff(upperdir)
        qpath, qfiles, qbytes = quarantine_upper(upperdir, quarantine_root, pid)
        rollback_overlay(upperdir, workdir)
        kill_pid(pid)
        clear_manual_decision(control_dir, pid)
        return ContainmentResult(
            pid=pid, decision_ts=decision_ts, frozen_ts=None, freeze_latency_s=None,
            bytes_at_risk=bytes_at_risk, files_at_risk=files_at_risk,
            policy=RollbackPolicy.MANUAL, rolled_back=True, killed=True,
            quarantine_path=qpath, quarantined_files=qfiles, quarantined_bytes=qbytes,
        )
    raise ValueError(f"Unknown decision: {decision}")
