"""
Operating Mode and Monitor-First Lifecycle Manager for AdaptShield.

Coordinates operating modes (monitor, protect, learn) and manages the
monitor-first transition period (default 24 hours before auto-switching to protect).
"""
from __future__ import annotations

import time
from typing import Any, Dict

from .config import AdaptShieldConfig
from .logging.logger import get_logger

logger = get_logger("adaptshield.mode")


class ModeManager:
    """
    Manages the runtime operating mode and handles monitor-first grace periods.
    """
    def __init__(
        self,
        config: AdaptShieldConfig,
        started_at: float | None = None,
    ):
        self.configured_mode = config.mode.lower()
        self.monitor_first_period_hours = float(config.monitor_first_period_hours)
        self.started_at = started_at if started_at is not None else time.time()
        self._manual_override: str | None = None

    @property
    def monitor_first_duration_seconds(self) -> float:
        return self.monitor_first_period_hours * 3600.0

    def is_monitor_first_active(self) -> bool:
        """Returns True if the agent is still within the initial monitor-first window."""
        if self._manual_override is not None:
            return False
        if self.configured_mode != "protect":
            return False
        if self.monitor_first_period_hours <= 0:
            return False
        elapsed = time.time() - self.started_at
        return elapsed < self.monitor_first_duration_seconds

    def remaining_monitor_first_seconds(self) -> float:
        """Returns remaining seconds in monitor-first mode, or 0.0 if expired."""
        if not self.is_monitor_first_active():
            return 0.0
        elapsed = time.time() - self.started_at
        return max(0.0, self.monitor_first_duration_seconds - elapsed)

    def get_active_mode(self) -> str:
        """
        Determines the current active operating mode.
        If in protect mode but monitor-first has not elapsed, returns 'monitor'.
        """
        if self._manual_override is not None:
            return self._manual_override

        if self.is_monitor_first_active():
            return "monitor"

        return self.configured_mode

    def set_mode(self, mode: str):
        """Allows manual runtime switching of the operating mode."""
        mode = mode.lower()
        if mode not in {"monitor", "protect", "learn"}:
            raise ValueError(f"Invalid mode '{mode}'. Must be monitor, protect, or learn.")
        self._manual_override = mode
        logger.info("[MODE] Operating mode manually set to '%s'.", mode)

    def reload_config(self, config: AdaptShieldConfig):
        """Applies reloaded config settings to the mode manager."""
        self.configured_mode = config.mode.lower()
        self.monitor_first_period_hours = float(config.monitor_first_period_hours)
        self._manual_override = None

    def get_status(self) -> Dict[str, Any]:
        """Provides status report on active mode and grace period."""
        active = self.get_active_mode()
        monitor_first = self.is_monitor_first_active()
        remaining = self.remaining_monitor_first_seconds()

        return {
            "active_mode": active,
            "configured_mode": self.configured_mode,
            "monitor_first_active": monitor_first,
            "monitor_first_remaining_hours": round(remaining / 3600.0, 2),
            "manual_override": self._manual_override is not None,
        }
