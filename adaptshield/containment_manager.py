"""
Containment using stock Linux primitives only -- no custom filesystem
(this is the direct point of differentiation from GuardFS, see roadmap
Sec 1.7).

THREE CONTAINMENT POLICIES, chosen with --rollback-policy on the daemon,
each a genuine, distinct research configuration for the ablation in
roadmap Sec 8.1 item 4:

  * NONE      -- freeze only. Process is paused (cgroups v2 freezer), no
                 further action. Safest choice if you are worried about
                 false positives destroying legitimate work -- an operator
                 can inspect and manually release later. This was the
                 ONLY policy actually wired into the daemon in the
                 previous version of this repo; the other two are new.

  * IMMEDIATE -- freeze, quarantine (copy) every file the overlay diff
                 shows was touched, THEN roll back (discard the overlay's
                 upper layer, restoring the pristine lower layer), THEN
                 kill the now-empty-handed process. This is "reversible"
                 in the sense that mattered in the roadmap: the FILESYSTEM
                 state is restored, and the touched files are preserved
                 in quarantine for forensics/possible recovery rather than
                 being silently deleted. The PROCESS itself is not
                 resumed, because resuming a confirmed ransomware process
                 after undoing its work would just cause it to redo the
                 damage -- there is no research value in reversibility at
                 the process level once you are confident enough to roll
                 back the files.

  * MANUAL    -- freeze immediately (fast, automatic), then WAIT for a
                 human operator decision instead of auto-rollback. Models
                 a human-in-the-loop SOC workflow. The operator uses
                 containment_cli.py to either RELEASE (unfreeze, false
                 positive) or CONFIRM (quarantine+rollback+kill, true
                 positive). This is the policy that makes "reversible"
                 literally true at the process level too: a released
                 process resumes exactly where it was frozen, undamaged.

Additionally (kept from the previous version, unchanged in behavior):
  * seccomp-bpf denial is intentionally NOT implemented anywhere in this
    repo. Installing a seccomp filter into an already-running,
    uncooperative process requires ptrace-based syscall injection
    (PTRACE_SEIZE + forcing a seccomp() syscall via direct register
    manipulation) -- a real technique, but one that is fragile across
    kernel/arch versions and, done incorrectly, can corrupt or crash the
    target process. I chose not to ship untested register-manipulation
    code with no way to verify it in this environment. Freezing already
    stops all further syscalls, which is sufficient for every policy
    above; treat seccomp injection as a genuine stretch goal only if a
    team member wants to implement and carefully test it themselves on
    real hardware.
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


# --------------------------------------------------------------------
# cgroup freezer (unchanged mechanism, still the required primary layer)
# --------------------------------------------------------------------

def ensure_cgroup_ready():
    """Create the adaptshield cgroup and enable the freezer controller.
    Must be run once as root before the daemon starts (see README)."""
    ADAPTSHIELD_CGROUP.mkdir(exist_ok=True)
    subtree_control = CGROUP_ROOT / "cgroup.subtree_control"
    current = subtree_control.read_text()
    if "+freezer" not in current and "freezer" not in current:
        try:
            subtree_control.write_text("+freezer")
        except OSError as e:
            raise RuntimeError(
                "Could not enable freezer controller in cgroup.subtree_control. "
                "You likely need to run as root: "
                f"echo '+freezer' | sudo tee {subtree_control}"
            ) from e


def freeze_pid(pid: int) -> float:
    """Move PID into the AdaptShield cgroup and freeze it. Returns the
    monotonic timestamp AFTER the freeze is CONFIRMED by the kernel
    (polls cgroup.events for 'frozen 1'), for accurate latency measurement."""
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
    """Resume every process in the AdaptShield cgroup. Used both by the
    MANUAL policy's RELEASE decision and available for direct/manual use."""
    (ADAPTSHIELD_CGROUP / "cgroup.freeze").write_text("0")


def kill_pid(pid: int):
    """Terminates the process. Used ONLY after quarantine+rollback has
    already run (IMMEDIATE/CONFIRM paths) or standalone for the
    'irreversible baseline' ablation (roadmap Sec 8.1 item 4) via
    --kill-instead-of-freeze, which bypasses freezing entirely."""
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass  # already gone -- not an error for our purposes


# --------------------------------------------------------------------
# overlayfs damage measurement + quarantine + rollback
# --------------------------------------------------------------------

def compute_overlay_diff(upperdir: str) -> tuple[int, int]:
    """Returns (bytes_at_risk, files_at_risk) by walking the overlayfs
    upper directory, which contains EXACTLY the files created or modified
    since the overlay was mounted."""
    total_bytes = 0
    total_files = 0
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
    """Copies (not moves) every file in the overlay upper directory into
    a timestamped quarantine folder BEFORE rollback discards it. This is
    what makes rollback a real "recovery" action instead of destructive
    deletion: encrypted/renamed copies are preserved for forensics or
    potential future decryption, while the live filesystem is restored.

    Returns (quarantine_path, files_copied, bytes_copied).
    """
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = Path(quarantine_root) / f"pid{pid}_{ts}"
    dest.mkdir(parents=True, exist_ok=True)

    files_copied = 0
    bytes_copied = 0
    upper = Path(upperdir)
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
            except OSError as e:
                print(f"[containment_manager] quarantine: failed to copy {src}: {e}")

    manifest = {
        "pid": pid, "timestamp": ts, "source_upperdir": upperdir,
        "files_copied": files_copied, "bytes_copied": bytes_copied,
    }
    (dest / "_manifest.json").write_text(json.dumps(manifest, indent=2))
    return str(dest), files_copied, bytes_copied


def rollback_overlay(upperdir: str, workdir: str):
    """Discards all changes since the overlay was mounted by wiping
    upperdir + workdir back to empty. After this, the merged view shows
    ONLY the pristine lowerdir contents again -- i.e. the filesystem is
    restored to its pre-attack state. ALWAYS quarantine (see above)
    before calling this if you want the touched files preserved."""
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
# manual-decision control channel (simple, dependency-free file-based IPC)
# --------------------------------------------------------------------

def _control_file(control_dir: str, pid: int) -> Path:
    return Path(control_dir) / f"decision_pid{pid}.json"


def request_manual_decision(control_dir: str, pid: int, evidence: dict):
    """Called by the daemon when policy=MANUAL reaches CRITICAL: writes a
    'pending' file the operator (via containment_cli.py) will overwrite
    with their decision. The daemon polls for this file changing."""
    Path(control_dir).mkdir(parents=True, exist_ok=True)
    _control_file(control_dir, pid).write_text(json.dumps({
        "pid": pid, "status": "pending", "evidence": evidence,
        "requested_at": time.time(),
    }, indent=2))


def check_manual_decision(control_dir: str, pid: int) -> str | None:
    """Returns 'release', 'confirm', or None (still pending / no file)."""
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
# top-level entry point used by daemon.py
# --------------------------------------------------------------------

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
        except (TimeoutError, ProcessLookupError, PermissionError) as e:
            print(f"[containment_manager] freeze failed for pid {pid}: {e}")
    else:
        # irreversible baseline ablation: skip freeze entirely, kill immediately
        kill_pid(pid)

    bytes_at_risk, files_at_risk = compute_overlay_diff(upperdir)
    result = ContainmentResult(
        pid=pid, decision_ts=decision_ts, frozen_ts=frozen_ts,
        freeze_latency_s=freeze_latency, bytes_at_risk=bytes_at_risk,
        files_at_risk=files_at_risk, policy=policy,
        killed=not use_freeze,
    )

    if not use_freeze:
        return result  # irreversible baseline: nothing further to do

    if policy == RollbackPolicy.NONE:
        return result  # freeze-only; operator can call unfreeze_pid() manually later

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
    """Called by the daemon's poll loop once check_manual_decision() returns
    a non-None value for a pid that is awaiting a decision."""
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
