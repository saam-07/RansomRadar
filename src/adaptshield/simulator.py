"""
AdaptShield Workload Simulator.

Safely simulates benign activity and ransomware-like filesystem behaviors
(high-frequency modifications and extension-altering renames) strictly inside
a dedicated sandbox directory.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .config import AdaptShieldConfig, load_config
from .detection.fanotify_ctypes import is_path_excluded
from .logging.logger import get_logger

logger = get_logger("adaptshield.simulator")

FORBIDDEN_ROOT_DIRS = {
    Path("/"),
    Path("/usr"),
    Path("/etc"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
    Path("/boot"),
    Path("/proc"),
    Path("/sys"),
    Path("/dev"),
    Path("/run"),
}


def is_forbidden_root_dir(path: Path | str) -> bool:
    try:
        raw_str = str(path).strip().replace("\\", "/")
        if raw_str in ("/", ""):
            return True
        norm = Path(path).resolve()
        # Protect filesystem root anchor (e.g. '/' on Linux or 'C:\' on Windows)
        if norm == Path(norm.anchor):
            return True
        posix = norm.as_posix()
        for f in FORBIDDEN_ROOT_DIRS:
            f_posix = f.as_posix()
            if (
                posix == f_posix
                or posix.endswith(f_posix)
                or raw_str == f_posix
                or norm == f.resolve()
            ):
                return True
    except Exception:
        pass
    return False


def set_sim_process_name(name: str = "ransom_worker"):
    """
    Sets Linux process comm name via prctl(PR_SET_NAME) so that the simulated
    process is identified as a distinct, non-immune test workload rather than
    the allowlisted 'adaptshield' CLI or 'python' runtime.
    """
    if sys.platform != "linux":
        return
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        name_bytes = name.encode("utf-8")[:15]
        # PR_SET_NAME = 15
        libc.prctl(15, name_bytes, 0, 0, 0)
    except Exception as e:
        logger.debug("Could not set process name via prctl: %s", e)


def is_path_under_watched(path: Path, watch_paths: list[str]) -> bool:
    """Checks whether a path is located within any configured watched directory."""
    try:
        norm = path.resolve()
        for wp in watch_paths:
            norm_wp = Path(wp).resolve()
            if norm == norm_wp or norm_wp in norm.parents:
                return True
    except Exception:
        pass
    return False


def resolve_sandbox_dir(
    target_arg: str | Path | None = None,
    sim_type: str = "ransomware",
    cfg: AdaptShieldConfig | None = None,
) -> Path:
    """
    Determines and prepares a safe, dedicated sandbox directory.
    Prefers a location under a watched path (e.g. /home/<user>/adaptshield_sim_<type>
    or /home/adaptshield_sim_<type>) while ensuring critical system directories and
    excluded directories are protected.
    """
    if cfg is None:
        try:
            cfg = load_config()
        except Exception:
            cfg = AdaptShieldConfig()

    dir_name = f"adaptshield_sim_{sim_type}"

    # 1. Explicit target path provided by operator
    if target_arg:
        if is_forbidden_root_dir(target_arg):
            raise ValueError(f"Refusing to use critical system path as sandbox: {target_arg}")
        target = Path(target_arg).resolve()
        if is_forbidden_root_dir(target):
            raise ValueError(f"Refusing to use critical system path as sandbox: {target}")

        # Safety check: warning if located in excluded path
        if is_path_excluded(str(target), cfg.watch.excludes):
            logger.warning(
                "Sandbox path '%s' is inside an excluded path. Agent will ignore events.",
                target,
            )

        # Guidance if not under a watched path
        if not is_path_under_watched(target, cfg.watch.paths):
            logger.warning(
                "Sandbox path '%s' is not under any watched path (%s). Agent might not observe events.",
                target,
                cfg.watch.paths,
            )

        target.mkdir(parents=True, exist_ok=True)
        return target

    # 2. Prefer user home directory if it is under a watched path (e.g. /home/user)
    try:
        user_home = Path.home().resolve()
        if is_path_under_watched(user_home, cfg.watch.paths):
            candidate = user_home / dir_name
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
    except Exception:
        pass

    # 3. Check configured watched paths directly (e.g. /home/adaptshield_sim_ransomware)
    for wp in cfg.watch.paths:
        try:
            wp_path = Path(wp).resolve()
            if wp_path.exists() and not is_forbidden_root_dir(wp_path):
                candidate = wp_path / dir_name
                candidate.mkdir(parents=True, exist_ok=True)
                return candidate
        except (PermissionError, OSError):
            continue

    # 4. Check /home directly
    home_dir = Path("/home")
    if home_dir.exists():
        try:
            candidate = home_dir / dir_name
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except (PermissionError, OSError):
            pass

    # 5. Fallback: temporary directory or user home
    try:
        candidate = Path.home() / dir_name
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except Exception:
        fallback = Path(tempfile.gettempdir()) / dir_name
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def simulate_benign_workload(
    target_dir: Path,
    count: int = 20,
    delay: float = 0.05,
) -> dict[str, Any]:
    """
    Generates standard benign document creation and editing with gentle write pauses.
    Produces low modification rates and zero file rename operations.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    created = []
    for i in range(count):
        p = target_dir / f"benign_doc_{i:03d}.txt"
        p.write_text(f"Benign document content for test record {i}.\n" * 10)
        created.append(str(p))
        if delay > 0:
            time.sleep(delay)

    return {
        "sim_type": "benign",
        "pid": os.getpid(),
        "target_dir": str(target_dir),
        "files_created": len(created),
        "modifications": len(created),
        "renames": 0,
    }


def simulate_ransomware_workload(
    target_dir: Path,
    count: int = 120,
    rounds: int = 2,
    burst_delay: float = 0.001,
) -> dict[str, Any]:
    """
    Safely simulates ransomware behavior strictly within target_dir:
    1. Sets process identity to 'ransom_worker' via prctl (on Linux) to ensure
       it is treated as non-immune user activity.
    2. Seeds target_dir with plain files.
    3. Rapidly overwrites each file with pseudo-encrypted bytes and renames to .locked.
    4. Repeats for 'rounds' to sustain modification and rename activity above
       rule-based containment thresholds (mod_rate >= 80/s, rename_rate >= 30/s).
    """
    set_sim_process_name("ransom_worker")
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Seed plain files
    file_paths: list[Path] = []
    for i in range(count):
        p = target_dir / f"work_doc_{i:03d}.txt"
        try:
            p.write_text(f"Important financial record or document {i}\n" * 16)
            file_paths.append(p)
        except OSError:
            pass

    total_mods = 0
    total_renames = 0

    # 2. Rapid modification and extension-altering rename bursts
    for r in range(rounds):
        ext = f".locked{r}" if r > 0 else ".locked"
        new_paths: list[Path] = []

        for p in file_paths:
            if not p.exists():
                continue
            try:
                # Payload overwrite (generates FAN_MODIFY and FAN_CLOSE_WRITE)
                ciphertext = os.urandom(1024)
                p.write_bytes(ciphertext)
                total_mods += 1

                # Extension alteration (generates FAN_MOVED_FROM and FAN_MOVED_TO)
                target_p = p.with_name(p.stem + ext)
                p.rename(target_p)
                total_renames += 1
                new_paths.append(target_p)

                if burst_delay > 0:
                    time.sleep(burst_delay)
            except OSError:
                break

        file_paths = new_paths

    return {
        "sim_type": "ransomware",
        "pid": os.getpid(),
        "target_dir": str(target_dir),
        "files": len(file_paths),
        "modifications": total_mods,
        "renames": total_renames,
    }


def run_simulation(
    sim_type: str,
    target: str | Path | None = None,
    count: int = 120,
    duration: float = 6.0,
    cfg: AdaptShieldConfig | None = None,
    in_process: bool = True,
) -> dict[str, Any]:
    """
    Executes a workload simulation in a safe sandbox directory.
    """
    if cfg is None:
        try:
            cfg = load_config()
        except Exception:
            cfg = AdaptShieldConfig()

    target_dir = resolve_sandbox_dir(target_arg=target, sim_type=sim_type, cfg=cfg)

    if sim_type == "benign":
        return simulate_benign_workload(target_dir, count=min(count, 20))

    # Ransomware workload
    return simulate_ransomware_workload(target_dir, count=count)


def cleanup_sandbox(target_dir: Path):
    """Safely cleans up files created inside a simulation sandbox."""
    if not target_dir.exists():
        return
    # Only remove if directory name matches our simulation naming pattern
    name = target_dir.name
    if "adaptshield_sim_" in name or "_sim_" in name or name.startswith("sim_"):
        try:
            shutil.rmtree(target_dir, ignore_errors=True)
        except Exception:
            pass
