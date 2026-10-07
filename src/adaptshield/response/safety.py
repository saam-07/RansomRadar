"""
Safety rails, process immunity, rate limiting, and storm panic switch for AdaptShield.
Prevents containment of critical system processes, kernel threads, self processes,
and prevents false-positive storm outages.
"""
from __future__ import annotations

import fnmatch
import os
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..config import AdaptShieldConfig, load_config
from ..logging.logger import get_logger

logger = get_logger("adaptshield.safety")

# Hard-coded absolute critical process names that can NEVER be contained
ABSOLUTE_PROTECTED_PROCESSES = {
    "init",
    "systemd",
    "systemd-journald",
    "systemd-udevd",
    "systemd-logind",
    "systemd-resolved",
    "sshd",
    "dbus-daemon",
    "login",
    "agetty",
    "dockerd",
    "containerd",
    "kthreadd",
}


class SafetyRails:
    def __init__(self, config: AdaptShieldConfig | None = None):
        self.config = config or load_config()
        self.self_pid = os.getpid()
        self.max_per_minute = self.config.safety_rails.max_containments_per_minute
        self.storm_threshold = self.config.safety_rails.storm_threshold_distinct_pids
        self.storm_window = self.config.safety_rails.storm_window_seconds

        # Rate limiting and storm tracking
        self._containment_timestamps: deque[float] = deque()
        self._storm_pids: deque[tuple[float, int]] = deque()
        self._storm_pids: deque[Tuple[float, int]] = deque()
        self.panic_switch_tripped: bool = False

    def is_self_or_child(self, pid: int) -> bool:
        """Returns True if the PID is the agent daemon itself or related process."""
        if pid == self.self_pid:
            return True
        try:
            ppid = os.getppid()
            if pid == ppid:
                return True
        except Exception:
            pass
        return False

    def is_kernel_thread(self, pid: int) -> bool:
        """Determines if a PID is a Linux kernel thread (PPID 2 or kthread)."""
        if pid <= 2:
            return True
        stat_path = Path(f"/proc/{pid}/stat")
        if stat_path.exists():
            try:
                content = stat_path.read_text().split()
                if len(content) > 3:
                    ppid = int(content[3])
                    if ppid == 2:  # Child of kthreadd
                        return True
            except (OSError, ValueError):
                pass
        return False

    def is_immune(
        self,
        pid: int,
        process_name: str | None = None,
        exe_path: str | None = None,
        username: str | None = None,
    ) -> tuple[bool, str]:
        process_name: Optional[str] = None,
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether a PID is immune from containment.
        Returns (is_immune, reason).
        """
        # 1. PID 1 Protection
        if pid == 1:
            return True, "PID 1 (init / systemd root)"

        # 2. Self and Parent Protection
        if self.is_self_or_child(pid):
            return True, "Agent daemon self/parent process"

        # 3. Kernel Threads Protection
        if self.is_kernel_thread(pid):
            return True, "Linux kernel thread"

        # 4. Resolve process name if not provided
        if not process_name:
            comm_path = Path(f"/proc/{pid}/comm")
            if comm_path.exists():
                try:
                    process_name = comm_path.read_text().strip()
                except OSError:
                    pass

        # 5. Check absolute critical system processes
        if process_name:
            name_lower = process_name.lower()
            if name_lower in ABSOLUTE_PROTECTED_PROCESSES:
                return True, f"Absolute protected system process: {process_name}"

            for pattern in ABSOLUTE_PROTECTED_PROCESSES:
                if fnmatch.fnmatch(name_lower, pattern):
                    return True, f"System process pattern match: {pattern}"

        # 6. Check Configured Allowlist Process Names
        if process_name:
            for allowed in self.config.allowlist.process_names:
                if fnmatch.fnmatch(process_name.lower(), allowed.lower()):
                    return True, f"Allowlisted process name: {allowed}"

        # 7. Check Configured Allowlist Exe Paths
        if exe_path:
            for allowed_exe in self.config.allowlist.exe_paths:
                if fnmatch.fnmatch(exe_path, allowed_exe):
                    return True, f"Allowlisted executable path: {allowed_exe}"

        # 8. Check Configured Allowlist Users
        if username and username in self.config.allowlist.users:
            return True, f"Allowlisted user: {username}"

        return False, ""

    def check_containment_permitted(self, pid: int) -> tuple[bool, str]:
    def check_containment_permitted(self, pid: int) -> Tuple[bool, str]:
        """
        Evaluates rate limits and false-positive storm conditions.
        Returns (permitted, reason).
        """
        now = time.monotonic()

        # If panic switch was already tripped, drop actions to monitor
        if self.panic_switch_tripped:
            return False, "Storm panic switch active: containment locked in MONITOR mode"

        # Clean old timestamps
        cutoff_rate = now - 60.0
        while self._containment_timestamps and self._containment_timestamps[0] < cutoff_rate:
            self._containment_timestamps.popleft()

        cutoff_storm = now - self.storm_window
        while self._storm_pids and self._storm_pids[0][0] < cutoff_storm:
            self._storm_pids.popleft()

        # Check False-Positive Storm Panic Switch
        self._storm_pids.append((now, pid))
        distinct_pids = {p for _t, p in self._storm_pids}
        if len(distinct_pids) >= self.storm_threshold:
            self.panic_switch_tripped = True
            logger.critical(
                "[STORM PANIC SWITCH TRIPPED] %d distinct PIDs triggered within %.1fs! "
                "Dropping automatically to MONITOR mode to prevent system lockup.",
                len(distinct_pids),
                self.storm_window,
            )
            return False, f"False-positive storm panic switch tripped ({len(distinct_pids)} distinct PIDs)"

        # Check Rate Limit (max N per minute)
        if len(self._containment_timestamps) >= self.max_per_minute:
            logger.warning(
                "[RATE LIMIT] Containment rate limit reached (%d/min). Suppressing action on PID=%s.",
                self.max_per_minute,
                pid,
            )
            return False, f"Rate limit reached ({self.max_per_minute}/min)"

        self._containment_timestamps.append(now)
        return True, "Containment permitted"

    def reset_panic_switch(self):
        """Allows operator to reset the panic switch after investigation."""
        self.panic_switch_tripped = False
        self._storm_pids.clear()
        logger.info("Storm panic switch reset by operator.")

    def is_self_exclusion_path(self, path: str) -> bool:
        """Checks if a filesystem path belongs to AdaptShield's own state/quarantine dirs."""
        p = Path(path).resolve()
        excluded = [
            Path(self.config.response.quarantine_dir).resolve(),
            Path(self.config.response.control_dir).resolve(),
            Path(self.config.logging.file).parent.resolve(),
            Path(self.config.telemetry.dir).resolve(),
        ]
        for exc in excluded:
            if p == exc or exc in p.parents:
                return True
        return False
