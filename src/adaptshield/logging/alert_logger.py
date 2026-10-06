"""
Structured alert logger for AdaptShield.
Replaces bare print() with structured logging and provides rotating JSONL records.
"""
import json
import os
import time
from pathlib import Path

from .logger import get_logger

logger = get_logger("adaptshield.alerts")


class AlertLogger:
    """Logs security telemetry and containment actions as structured JSONL records.
    Replaces bare print() statements with leveled structured logger calls.
    """

    def __init__(self, log_path: str = "/var/log/adaptshield/alert.jsonl", max_bytes: int = 10 * 1024 * 1024):
        self.log_path = Path(log_path)
        self.max_bytes = max_bytes
        self._ensure_dir()

    def _ensure_dir(self):
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            # Fallback for unprivileged / sandbox environments
            fallback_dir = Path("results/logs")
            fallback_dir.mkdir(parents=True, exist_ok=True)
            self.log_path = fallback_dir / self.log_path.name

    def _rotate_if_needed(self):
        try:
            if self.log_path.exists() and self.log_path.stat().st_size >= self.max_bytes:
                rotated = self.log_path.with_name(f"{self.log_path.name}.1")
                if rotated.exists():
                    rotated.unlink()
                self.log_path.rename(rotated)
        except Exception as e:
            logger.debug("Failed rotating alert log: %s", e)

    def log(self, event_type: str, **fields):
        """Records an event to the JSONL log file and emits a structured log message."""
        record = {
            "ts": time.time(),
            "event_type": event_type,
            **fields,
        }

        self._rotate_if_needed()

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except (PermissionError, OSError) as e:
            self._ensure_dir()
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception as ex:
                logger.error("Failed writing alert log: %s", ex)

        # Emit structured log output according to event severity
        pid = fields.get("pid")
        if event_type == "alert_critical":
            risk_ewma = fields.get("risk_ewma", 0.0)
            evidence = fields.get("evidence", {})
            logger.warning(
                "[ALERT CRITICAL] Containment triggered for PID=%s | risk_ewma=%.3f | evidence_features=%s",
                pid,
                risk_ewma,
                list(evidence.keys()) if isinstance(evidence, dict) else evidence,
            )
        elif event_type == "containment":
            policy = fields.get("policy", "unknown")
            action = "KILLED" if fields.get("killed") else ("FROZEN" if fields.get("policy") != "none" else "FLAGGED")
            rolled_back = fields.get("rolled_back", False)
            logger.warning(
                "[CONTAINMENT] PID=%s action=%s policy=%s rolled_back=%s files_at_risk=%s",
                pid,
                action,
                policy,
                rolled_back,
                fields.get("files_at_risk", 0),
            )
        elif event_type == "escalation":
            logger.info(
                "[ESCALATION] Tier-1 activated for PID=%s | tier0_score=%.3f | latency=%.4fs",
                pid,
                fields.get("tier0_score", 0.0),
                fields.get("escalation_latency_s", 0.0),
            )
        elif event_type == "manual_decision_applied":
            logger.info(
                "[OPERATOR DECISION] PID=%s decision=%s applied",
                pid,
                fields.get("decision"),
            )
        else:
            logger.info("[EVENT] %s for PID=%s: %s", event_type, pid, fields)
