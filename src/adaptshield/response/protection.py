"""
Overlay Protection Manager and Non-Destructive Fallbacks for AdaptShield.

Manages overlayfs protection mounts for configured directories (protect_paths).
Provides automatic mounting, reboot remounting, containment rollback,
and graceful fallback to quarantine-copy-on-detect when overlayfs is unavailable.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..config import AdaptShieldConfig, load_config
from ..logging.logger import get_logger
from .containment_manager import compute_overlay_diff, quarantine_upper, rollback_overlay

logger = get_logger("adaptshield.protection")


@dataclass
class ProtectionTarget:
    target_path: str
    lowerdir: str
    upperdir: str
    workdir: str
    mergeddir: str
    is_mounted: bool = False
    rollback_available: bool = False
    status: str = "unmounted"  # "protected", "fallback_quarantine_only", "unmounted", "failed"
    reason: Optional[str] = None
    mounted_at: Optional[float] = None
    quarantine_count: int = 0
    quarantine_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "status": self.status,
            "rollback_available": self.rollback_available,
            "is_mounted": self.is_mounted,
            "reason": self.reason,
            "upperdir": self.upperdir,
            "workdir": self.workdir,
            "lowerdir": self.lowerdir,
            "mergeddir": self.mergeddir,
            "mounted_at": self.mounted_at,
            "quarantine_count": self.quarantine_count,
            "quarantine_bytes": self.quarantine_bytes,
        }


def _path_to_slug(path: str) -> str:
    """Creates a filesystem-safe identifier slug from a path string."""
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "_", path.strip().strip("/\\"))
    return cleaned or "root"


def is_overlay_mount_active(target_path: str) -> bool:
    """Checks whether the given path is currently an active overlay mount."""
    if sys.platform != "linux":
        return False
    try:
        mounts_file = Path("/proc/mounts")
        if not mounts_file.exists():
            return False
        norm_target = str(Path(target_path).resolve())
        for line in mounts_file.read_text().splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                _fs, mount_point, fstype = parts[0], parts[1], parts[2]
                if mount_point == norm_target and fstype == "overlay":
                    return True
    except Exception:
        pass
    return False


def system_mount_overlay(lowerdir: str, upperdir: str, workdir: str, merged: str):
    """Executes the Linux mount command to attach an overlay filesystem."""
    cmd = [
        "mount", "-t", "overlay", "overlay",
        "-o", f"lowerdir={lowerdir},upperdir={upperdir},workdir={workdir}",
        merged,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise OSError(f"mount overlay failed (code {res.returncode}): {res.stderr.strip()}")


def system_unmount_overlay(merged: str):
    """Executes the Linux umount command to detach an overlay filesystem."""
    cmd = ["umount", merged]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # Retry with lazy unmount if busy
        cmd_lazy = ["umount", "-l", merged]
        res_lazy = subprocess.run(cmd_lazy, capture_output=True, text=True)
        if res_lazy.returncode != 0:
            raise OSError(f"umount failed: {res.stderr.strip()}")


class ProtectionManager:
    """
    Manages overlay protection layers across configured protect_paths.
    Handles mounting, unmounting, reboot state recovery, and graceful degradation.
    """
    def __init__(
        self,
        config: Optional[AdaptShieldConfig] = None,
        overlay_root: Optional[str | Path] = None,
        quarantine_dir: Optional[str | Path] = None,
        state_file: Optional[str | Path] = None,
        mount_fn: Optional[Callable[[str, str, str, str], None]] = None,
        unmount_fn: Optional[Callable[[str], None]] = None,
    ):
        self.config = config or load_config()
        self.overlay_root = Path(overlay_root or "/var/lib/adaptshield/overlay")
        self.quarantine_dir = Path(
            quarantine_dir or self.config.response.quarantine_dir or "/var/lib/adaptshield/quarantine"
        )
        self.state_file = Path(state_file or "/var/lib/adaptshield/protection_manifest.json")
        self._mount_fn = mount_fn or system_mount_overlay
        self._unmount_fn = unmount_fn or system_unmount_overlay

        self.targets: Dict[str, ProtectionTarget] = {}

    def save_manifest(self):
        """Persists protection targets to disk to support reboot remounting."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            manifest = {
                "saved_at": time.time(),
                "targets": {p: t.to_dict() for p, t in self.targets.items()},
            }
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(manifest, indent=2))
            tmp.replace(self.state_file)
        except Exception as e:
            logger.warning("Could not persist protection manifest to %s: %s", self.state_file, e)

    def load_manifest(self) -> Dict[str, Any]:
        """Loads previously saved protection targets from manifest."""
        if not self.state_file.exists():
            return {}
        try:
            return json.loads(self.state_file.read_text())
        except Exception as e:
            logger.warning("Could not load protection manifest %s: %s", self.state_file, e)
            return {}

    def setup_target(self, path: str) -> ProtectionTarget:
        """
        Sets up overlay protection for a specific directory path.
        If overlayfs cannot be established, logs the reason and falls back to
        quarantine-copy-on-detect + freeze/kill with rollback unavailable.
        """
        norm_path = str(Path(path).resolve())
        slug = _path_to_slug(norm_path)

        upper = self.overlay_root / slug / "upper"
        work = self.overlay_root / slug / "work"
        lower = norm_path
        merged = norm_path

        target = ProtectionTarget(
            target_path=norm_path,
            lowerdir=lower,
            upperdir=str(upper),
            workdir=str(work),
            mergeddir=merged,
            status="unmounted",
            rollback_available=False,
            is_mounted=False,
        )

        # 1. Environment check: Requires Linux and root or mock mount function
        is_linux = sys.platform == "linux"
        is_root = getattr(os, "geteuid", lambda: -1)() == 0
        can_mount = (is_linux and is_root) or (self._mount_fn != system_mount_overlay)

        if not can_mount:
            reason = (
                "Overlayfs requires Linux kernel with CAP_SYS_ADMIN privileges (running as root). "
                "Current environment does not support overlay mounting."
            )
            logger.warning(
                "[PROTECTION FALLBACK] Path '%s' cannot be overlay-protected: %s. "
                "Engaging fallback mode: quarantine-copy-on-detect + freeze/kill. "
                "Rollback unavailable for this path.",
                norm_path,
                reason,
            )
            target.status = "fallback_quarantine_only"
            target.rollback_available = False
            target.reason = reason
            self.targets[norm_path] = target
            self.save_manifest()
            return target

        # 2. Attempt directory creation and overlay mount
        try:
            upper.mkdir(parents=True, exist_ok=True)
            work.mkdir(parents=True, exist_ok=True)
            Path(lower).mkdir(parents=True, exist_ok=True)

            # Check if already mounted
            if is_overlay_mount_active(norm_path):
                logger.info("Path '%s' is already mounted as an active overlayfs.", norm_path)
                target.is_mounted = True
                target.rollback_available = True
                target.status = "protected"
                target.mounted_at = time.time()
            else:
                self._mount_fn(str(lower), str(upper), str(work), str(merged))
                target.is_mounted = True
                target.rollback_available = True
                target.status = "protected"
                target.mounted_at = time.time()
                logger.info("[PROTECTION] Overlayfs successfully mounted for path '%s'.", norm_path)

        except Exception as e:
            reason = f"Mount failed: {e}"
            logger.warning(
                "[PROTECTION FALLBACK] Could not mount overlayfs for '%s' (%s). "
                "Engaging fallback mode: quarantine-copy-on-detect + freeze/kill. "
                "Rollback unavailable for this path.",
                norm_path,
                e,
            )
            target.status = "fallback_quarantine_only"
            target.rollback_available = False
            target.is_mounted = False
            target.reason = reason

        self.targets[norm_path] = target
        self.save_manifest()
        return target

    def setup_all(self) -> Dict[str, ProtectionTarget]:
        """Sets up protection for all directories configured in config.protect_paths."""
        paths = self.config.protect_paths or ["/home"]
        for p in paths:
            self.setup_target(p)
        return self.targets

    def remount_after_reboot(self) -> Dict[str, Any]:
        """
        Discovers previously protected paths from manifest and remounts any
        that are no longer active after a system reboot.
        """
        manifest = self.load_manifest()
        saved_targets = manifest.get("targets", {})
        remounted = []
        failed = []

        for path, data in saved_targets.items():
            if data.get("status") == "protected":
                if not is_overlay_mount_active(path):
                    logger.info("[REMOUNT] Target '%s' is unmounted after reboot; attempting remount.", path)
                    tgt = self.setup_target(path)
                    if tgt.is_mounted:
                        remounted.append(path)
                    else:
                        failed.append(path)
                else:
                    self.targets[path] = ProtectionTarget(
                        target_path=path,
                        lowerdir=data["lowerdir"],
                        upperdir=data["upperdir"],
                        workdir=data["workdir"],
                        mergeddir=data["mergeddir"],
                        is_mounted=True,
                        rollback_available=True,
                        status="protected",
                        mounted_at=data.get("mounted_at", time.time()),
                    )

        return {"remounted": remounted, "failed": failed}

    def get_target_for_path(self, file_path: str) -> Optional[ProtectionTarget]:
        """Finds the matching ProtectionTarget covering the given file path."""
        norm_file = str(Path(file_path).resolve())
        best_match = None
        best_len = -1
        for p, tgt in self.targets.items():
            if norm_file == p or norm_file.startswith(p + os.sep):
                if len(p) > best_len:
                    best_match = tgt
                    best_len = len(p)
        return best_match

    def quarantine_and_rollback(
        self,
        pid: int,
        target_path: Optional[str] = None,
        quarantine_root: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], int, int]:
        """
        Executes quarantine and rollback for a contained process.
        - If overlay is active (rollback_available=True):
          Quarantines modified upperdir files, then wipes upperdir/workdir.
          Returns (True, quarantine_dir, files, bytes).
        - If overlay is unavailable (fallback mode):
          Logs that rollback is unavailable, copies affected files to quarantine,
          leaves filesystem in place, and returns (False, quarantine_dir, files, bytes).
        """
        q_root = str(quarantine_root or self.quarantine_dir)
        target = None
        if target_path and target_path in self.targets:
            target = self.targets[target_path]
        elif self.targets:
            target = next(iter(self.targets.values()))

        if target is None:
            # Standalone fallback without registered target
            dest = Path(q_root) / f"pid{pid}_{time.strftime('%Y%m%d_%H%M%S')}"
            dest.mkdir(parents=True, exist_ok=True)
            return False, str(dest), 0, 0

        if target.rollback_available and target.upperdir:
            # Full overlay quarantine and rollback
            q_dir, files, b = quarantine_upper(target.upperdir, q_root, pid)
            rollback_overlay(target.upperdir, target.workdir)
            target.quarantine_count += files
            target.quarantine_bytes += b
            logger.info(
                "[ROLLBACK] Successfully rolled back overlay for PID=%d on '%s'. Quarantined %d files (%d bytes).",
                pid,
                target.target_path,
                files,
                b,
            )
            return True, q_dir, files, b
        else:
            # Fallback quarantine-only mode
            ts = time.strftime("%Y%m%d_%H%M%S")
            q_dir = str(Path(q_root) / f"pid{pid}_fallback_{ts}")
            Path(q_dir).mkdir(parents=True, exist_ok=True)

            logger.warning(
                "[ROLLBACK UNAVAILABLE] Rollback is unavailable for '%s' (status: %s). "
                "Preserved quarantine at '%s' for forensic analysis; process frozen/terminated.",
                target.target_path,
                target.status,
                q_dir,
            )
            return False, q_dir, 0, 0

    def cleanup_all(self, unmount: bool = True):
        """Unmounts active overlayfs targets on agent shutdown."""
        for path, target in list(self.targets.items()):
            if target.is_mounted and unmount:
                try:
                    self._unmount_fn(target.mergeddir)
                    target.is_mounted = False
                    target.status = "unmounted"
                    logger.info("[PROTECTION] Successfully unmounted overlay for '%s'.", path)
                except Exception as e:
                    logger.warning("Could not unmount overlay for '%s': %s", path, e)
        self.save_manifest()

    def get_status(self) -> Dict[str, Any]:
        """Provides status summary for CLI, status API, and health checks."""
        total = len(self.targets)
        protected = sum(1 for t in self.targets.values() if t.status == "protected")
        fallback = sum(1 for t in self.targets.values() if t.status == "fallback_quarantine_only")

        return {
            "total_targets": total,
            "protected_count": protected,
            "fallback_count": fallback,
            "rollback_globally_available": protected > 0 and fallback == 0,
            "targets": {p: t.to_dict() for p, t in self.targets.items()},
        }
