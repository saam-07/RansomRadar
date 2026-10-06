"""
Rotating Telemetry Writer for AdaptShield.

Collects telemetry and feature rows under /var/lib/adaptshield/telemetry/
with file size rotation for offline data labeling, auditing, and retraining.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .logging.logger import get_logger

logger = get_logger("adaptshield.telemetry")


class TelemetryWriter:
    """
    Writes structured runtime telemetry and feature records with size-based rotation.
    Thread-safe and non-blocking.
    """
    def __init__(
        self,
        telemetry_dir: str | Path = "/var/lib/adaptshield/telemetry",
        rotation_mb: int = 50,
        enabled: bool = False,
    ):
        self.telemetry_dir = Path(telemetry_dir)
        self.rotation_bytes = max(1, rotation_mb) * 1024 * 1024
        self.enabled = enabled
        self._lock = threading.Lock()
        self._current_file: Optional[Path] = None
        self._file_handle = None
        self._current_bytes = 0

        if self.enabled:
            try:
                self.telemetry_dir.mkdir(parents=True, exist_ok=True)
                self._rotate()
            except Exception as e:
                logger.warning("Could not initialize telemetry directory %s: %s", self.telemetry_dir, e)
                self.enabled = False

    def _rotate(self):
        """Rotates the telemetry log file to a new timestamped file."""
        if self._file_handle:
            try:
                self._file_handle.flush()
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None

        ts = time.strftime("%Y%m%d_%H%M%S")
        self._current_file = self.telemetry_dir / f"telemetry_{ts}.jsonl"
        try:
            self._file_handle = open(self._current_file, "a", encoding="utf-8")
            self._current_bytes = self._current_file.stat().st_size if self._current_file.exists() else 0
            logger.info("[TELEMETRY] Rotated to new telemetry file: %s", self._current_file)
        except Exception as e:
            logger.warning("Could not open new telemetry file %s: %s", self._current_file, e)
            self._file_handle = None

    def record(
        self,
        pid: int,
        mode: str,
        risk_score: float,
        risk_level: str,
        action: str,
        features: Dict[str, Any],
        comm: Optional[str] = None,
        exe_path: Optional[str] = None,
        explanation: Optional[Dict[str, Any]] = None,
    ):
        """Records a single telemetry record."""
        if not self.enabled or not self._file_handle:
            return

        payload = {
            "timestamp": time.time(),
            "pid": pid,
            "comm": comm or f"pid_{pid}",
            "exe_path": exe_path or "unknown",
            "mode": mode,
            "risk_score": round(float(risk_score), 4),
            "risk_level": risk_level,
            "action": action,
            "features": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in features.items()},
            "explanation": explanation or {},
        }

        line = json.dumps(payload) + "\n"
        b_len = len(line.encode("utf-8"))

        with self._lock:
            if self._current_bytes + b_len >= self.rotation_bytes:
                self._rotate()

            if self._file_handle:
                try:
                    self._file_handle.write(line)
                    self._file_handle.flush()
                    self._current_bytes += b_len
                except Exception as e:
                    logger.debug("Failed writing telemetry record: %s", e)

    def flush(self):
        with self._lock:
            if self._file_handle:
                try:
                    self._file_handle.flush()
                except Exception:
                    pass

    def close(self):
        with self._lock:
            if self._file_handle:
                try:
                    self._file_handle.flush()
                    self._file_handle.close()
                except Exception:
                    pass
                self._file_handle = None
