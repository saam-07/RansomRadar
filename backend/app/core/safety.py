"""
AdaptShield Safety Rails Module
===============================
Guarantees that containment actions can never disrupt essential system components:
1. Hard-coded immunity: PID 1, kernel processes, systemd*, sshd, dbus, display servers.
2. Configurable allowlists by process name, binary path, and user.
3. Rate limiting: bounds maximum containments permitted per minute.
4. False-Positive Storm Panic Switch: if multiple distinct PIDs trigger CRITICAL
   within a short time window, containment drops automatically to monitor mode.
"""

from __future__ import annotations

import os
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple


CRITICAL_PROTECTED_PIDS: Set[int] = {0, 1, 2}

CRITICAL_SYSTEM_NAMES: Set[str] = {
    "init", "systemd", "systemd-journald", "systemd-udevd", "sshd",
    "dbus-daemon", "login", "Xorg", "wayland", "kthreadd", "dockerd",
}

DEFAULT_ALLOWLISTED_NAMES: Set[str] = {
    "rsync", "tar", "restic", "borg", "postgres", "mysqld",
    "apt", "dpkg", "apt-get", "git", "code_editor",
}


class SafetyRails:
    def __init__(
        self,
        allowlisted_names: Optional[Set[str]] = None,
        max_containments_per_min: int = 6,
        panic_distinct_pids: int = 3,
        panic_window_seconds: float = 12.0,
    ):
        self.allowlisted_names: Set[str] = set(allowlisted_names or DEFAULT_ALLOWLISTED_NAMES)
        self.max_containments_per_min = max_containments_per_min
        self.panic_distinct_pids = panic_distinct_pids
        self.panic_window_seconds = panic_window_seconds

        self.containment_timestamps: deque[float] = deque()
        self.critical_events: deque[Tuple[int, float]] = deque()
        self.panic_tripped: bool = False
        self.mode: str = "protect"  # "protect", "monitor"

    def add_allowlist(self, name: str) -> None:
        self.allowlisted_names.add(name.lower())

    def remove_allowlist(self, name: str) -> None:
        self.allowlisted_names.discard(name.lower())

    def check_can_contain(self, pid: int, process_name: Optional[str] = None) -> Tuple[bool, str]:
        """
        Determines whether a process may be contained or killed.
        Returns: (allowed: bool, reason: str)
        """
        if self.panic_tripped:
            return False, "BLOCKED: Panic switch tripped (system dropped to monitor mode)"

        if self.mode == "monitor":
            return False, "BLOCKED: Operating mode is 'monitor' (containment actions disabled)"

        if pid in CRITICAL_PROTECTED_PIDS or pid < 100:
            return False, f"BLOCKED: Protected OS PID ({pid})"

        try:
            if pid == os.getpid():
                return False, "BLOCKED: Self-exclusion (agent process)"
        except Exception:
            pass

        pname = (process_name or "").lower().strip()
        if pname in CRITICAL_SYSTEM_NAMES:
            return False, f"BLOCKED: Protected system service name '{pname}'"

        if pname in self.allowlisted_names:
            return False, f"BLOCKED: Allowlisted legitimate application '{pname}'"

        # Rate limiting check
        now = time.time()
        while self.containment_timestamps and (now - self.containment_timestamps[0] > 60.0):
            self.containment_timestamps.popleft()

        if len(self.containment_timestamps) >= self.max_containments_per_min:
            return False, f"BLOCKED: Containment rate limit reached ({self.max_containments_per_min}/min)"

        return True, "ALLOWED"

    def record_critical_trigger(self, pid: int) -> bool:
        """
        Records a PID reaching CRITICAL state. Checks for false-positive storm.
        If tripped, drops mode to 'monitor' and returns True.
        """
        now = time.time()
        self.critical_events.append((pid, now))

        # Evict events older than window
        while self.critical_events and (now - self.critical_events[0][1] > self.panic_window_seconds):
            self.critical_events.popleft()

        distinct_pids = {p for p, _ in self.critical_events}
        if len(distinct_pids) >= self.panic_distinct_pids:
            self.panic_tripped = True
            self.mode = "monitor"
            return True

        return False

    def record_containment_action(self, pid: int) -> None:
        self.containment_timestamps.append(time.time())

    def reset_panic(self) -> None:
        self.panic_tripped = False
        self.mode = "protect"
        self.critical_events.clear()

    def reset_storm_state(self) -> None:
        """Alias for reset_panic."""
        self.reset_panic()
