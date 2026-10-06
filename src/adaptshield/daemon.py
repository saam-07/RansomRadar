"""
AdaptShield Daemon -- detection and containment pipeline.
Takes NO required CLI arguments; everything comes from config with defaults.
Gracefully degrades to Tier-0-only mode when BCC or kernel kprobes are unavailable.
"""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd

from .config import AdaptShieldConfig, load_config
from .detection.feature_aggregator import FEATURE_COLUMNS, FeatureAggregator
from .detection.risk_scorer import RiskLevel, RiskScorer
from .detection.tier0_watcher import Tier0Watcher, tier0_suspicion_score
from .detection.tier1_bridge import Tier1Tracer, is_tier1_available
from .logging.alert_logger import AlertLogger
from .logging.logger import get_logger, setup_logging
from .ml.classifier import build_classifier
from .ml.explain import explain_alert
from .ml.selector import select_classifier
from .mode import ModeManager
from .response.containment_manager import (
    RollbackPolicy,
    check_manual_decision,
    contain,
    ensure_cgroup_ready,
    resolve_manual_decision,
    unfreeze_pid,
)
from .response.protection import ProtectionManager
from .response.safety import SafetyRails
from .state import StateManager
from .telemetry import TelemetryWriter

logger = get_logger("adaptshield.daemon")


class AdaptShieldDaemon:
    def __init__(
        self,
        watch_path: str = "/home",
        window_seconds: float = 2.0,
        theta0: float = 0.5,
        classifier_name: str = "xgboost",
        overlay_upperdir: str = "/var/lib/adaptshield/overlay_upper",
        overlay_workdir: str = "/var/lib/adaptshield/overlay_work",
        quarantine_dir: str = "/var/lib/adaptshield/quarantine",
        control_dir: str = "/var/lib/adaptshield/control",
        log_path: str = "/var/log/adaptshield/alert.jsonl",
        rollback_policy: RollbackPolicy = RollbackPolicy.IMMEDIATE,
        use_escalation: bool = True,
        use_tier1: bool = True,
        use_risk_smoothing: bool = True,
        use_freeze: bool = True,
        model=None,
        model_path: str | None = None,
        config: AdaptShieldConfig | None = None,
        dry_run: bool = False,
    ):
        self.config = config or load_config()
        self.dry_run = dry_run
        self.watch_path = watch_path
        self.window_seconds = window_seconds
        self.theta0 = theta0
        self.classifier_name = classifier_name
        self.overlay_upperdir = overlay_upperdir
        self.overlay_workdir = overlay_workdir
        self.quarantine_dir = quarantine_dir
        self.control_dir = control_dir
        self.rollback_policy = rollback_policy
        self.use_escalation = use_escalation
        self.use_risk_smoothing = use_risk_smoothing
        self.use_freeze = use_freeze

        # 0. Overlay Protection Manager (manages per-path overlayfs layers and fallbacks)
        self.protection = ProtectionManager(config=self.config)
        try:
            self.protection.setup_all()
        except Exception as e:
            logger.debug("ProtectionManager setup_all note: %s", e)

        # 1. Tier-0 Watcher (attempt initialization with fallback for non-Linux / sandbox)
        watch_paths = self.config.watch.paths if (self.config and self.config.watch.paths) else [watch_path]
        excludes = self.config.watch.excludes if (self.config and self.config.watch.excludes) else None
        try:
            self.tier0 = Tier0Watcher(watch_path=watch_paths, window_seconds=window_seconds, excludes=excludes)
            self.tier0_available = True
        except Exception as e:
            logger.warning("Fanotify unavailable on %s (%s); running in mock/sandbox watcher mode.", watch_paths, e)
            self.tier0 = None
            self.tier0_available = False

        # 2. Tier-1 eBPF Tracer (optional graceful degradation)
        self.tier1_available = False
        if use_tier1 and is_tier1_available():
            try:
                self.tier1 = Tier1Tracer()
                self.tier1_available = True
                logger.info("Tier-1 eBPF tracer initialized successfully.")
            except Exception as e:
                logger.warning("Tier-1 initialization failed (%s); degrading gracefully to Tier-0-only mode.", e)
                self.tier1 = None
                self.tier1_available = False
        else:
            self.tier1 = None
            self.tier1_available = False
            if use_tier1 and not is_tier1_available():
                logger.info("BCC/eBPF not available on this platform; running in Tier-0-only mode.")

        # 3. Feature Aggregator
        self.aggregator = FeatureAggregator(window_seconds=window_seconds)

        # 4. Classifier & Synthetic Guard Auto-Selection
        if model is not None:
            self.classifier = model
            self.classifier_metadata = {"name": "custom_instance", "synthetic": False}
        elif model_path and os.path.exists(model_path):
            self.classifier = build_classifier(classifier_name).load(model_path)
            self.classifier_metadata = {"name": Path(model_path).stem, "synthetic": False}
        else:
            self.classifier, self.classifier_metadata = select_classifier(self.config)

        # 5. Risk Scorer
        self.risk_scorer = RiskScorer(
            alpha=self.config.detection.ewma_alpha,
            watch_threshold=self.config.detection.thresholds.elevated,
            suspect_threshold=self.config.detection.thresholds.suspicious,
            critical_threshold=self.config.detection.thresholds.critical,
            critical_confirm_windows=self.config.detection.consecutive_windows_for_critical,
        )

        # 6. Mode Manager & Telemetry Writer
        self.mode_mgr = ModeManager(self.config)
        self.telemetry = TelemetryWriter(
            telemetry_dir=self.config.telemetry.dir,
            rotation_mb=self.config.telemetry.rotation_mb,
            enabled=self.config.telemetry.enabled,
        )

        # 6. Logger & Cgroups
        self.logger = AlertLogger(log_path)
        self._escalated_pids: set[int] = set()
        self._contained_pids: set[int] = set()
        self._awaiting_manual: set[int] = set()

        # 7. Safety Rails & State Recovery
        self.safety = SafetyRails(self.config)
        state_dir = Path(self.config.response.control_dir).parent
        self.state_mgr = StateManager(state_dir / "state.json")

        try:
            ensure_cgroup_ready()
        except Exception as e:
            logger.debug("cgroup v2 initialization skipped in userspace: %s", e)

        # Recover prior state if present
        try:
            recovery_summary = self.state_mgr.recover(self.config)
            if recovery_summary.get("recovered_count", 0) > 0:
                logger.info(
                    "State recovery processed %d processes on startup: %s",
                    recovery_summary["recovered_count"],
                    recovery_summary["actions"],
                )
        except Exception as e:
            logger.warning("Error recovering state on startup: %s", e)

    @classmethod
    def from_config(cls, cfg: AdaptShieldConfig | None = None, dry_run: bool = False) -> AdaptShieldDaemon:
        if cfg is None:
            cfg = load_config()

        watch_path = cfg.watch.paths[0] if cfg.watch.paths else "/home"
        upper = os.path.join(cfg.response.quarantine_dir, "upper")
        work = os.path.join(cfg.response.quarantine_dir, "work")

        return cls(
            watch_path=watch_path,
            window_seconds=cfg.detection.window_seconds,
            theta0=cfg.detection.theta0,
            classifier_name=cfg.classifier.model_name,
            overlay_upperdir=upper,
            overlay_workdir=work,
            quarantine_dir=cfg.response.quarantine_dir,
            control_dir=cfg.response.control_dir,
            log_path=cfg.logging.alert_file,
            rollback_policy=RollbackPolicy(cfg.response.policy),
            use_escalation=cfg.detection.use_escalation,
            use_tier1=cfg.detection.use_tier1,
            use_risk_smoothing=cfg.detection.use_risk_smoothing,
            use_freeze=cfg.response.use_freeze,
            model_path=cfg.classifier.model_path,
            config=cfg,
            dry_run=dry_run,
        )

    def _maybe_escalate(self, tier0_snapshot: dict):
        if not (self.use_escalation and self.tier1):
            return
        for pid, feats in tier0_snapshot.items():
            score = tier0_suspicion_score(feats)
            if score >= self.theta0 and pid not in self._escalated_pids:
                t_decide = time.monotonic()
                try:
                    self.tier1.escalate(pid)
                    t_active = time.monotonic()
                    self._escalated_pids.add(pid)
                    self.logger.log("escalation", pid=pid, tier0_score=score,
                                     escalation_latency_s=t_active - t_decide)
                except Exception as e:
                    logger.warning("Could not escalate PID %s in Tier-1: %s", pid, e)

    def _log_containment_result(self, pid: int, result):
        self.logger.log(
            "containment", pid=pid,
            policy=result.policy.value,
            freeze_latency_s=result.freeze_latency_s,
            bytes_at_risk=result.bytes_at_risk,
            files_at_risk=result.files_at_risk,
            rolled_back=result.rolled_back,
            killed=result.killed,
            quarantine_path=result.quarantine_path,
            quarantined_files=result.quarantined_files,
            quarantined_bytes=result.quarantined_bytes,
            awaiting_manual_decision=result.awaiting_manual_decision,
        )

    def _classify_and_score(self, rows: list[dict]):
        if not rows:
            return
        df = pd.DataFrame(rows)
        # Ensure all canonical feature columns exist with safe defaults
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = np.nan if col.startswith("t1_") else 0.0
        feature_df = df[FEATURE_COLUMNS]
        proba = self.classifier.predict_proba(feature_df)
        p_ransomware = proba[:, 1] if proba.shape[1] == 2 else proba[:, -1]

        for row, p in zip(rows, p_ransomware):
            pid = row["pid"]
            if self.use_risk_smoothing:
                level = self.risk_scorer.update(pid, float(p))
                ewma = self.risk_scorer.get_ewma(pid)
            else:
                level = RiskLevel.CRITICAL if p >= 0.85 else RiskLevel.NONE
                ewma = float(p)

            if level == RiskLevel.CRITICAL and pid not in self._contained_pids:
                # 1. Operating mode check & forensic explanation
                active_mode = self.mode_mgr.get_active_mode()
                expl = explain_alert(
                    self.classifier,
                    row,
                    self.classifier_metadata.get("classifier_type", "xgboost"),
                )

                if active_mode in ("monitor", "learn"):
                    self.logger.log("alert_critical", pid=pid, risk_ewma=ewma, mode=active_mode, evidence=row, explanation=expl)
                    self.telemetry.record(
                        pid=pid,
                        mode=active_mode,
                        risk_score=ewma,
                        risk_level="CRITICAL",
                        action=f"{active_mode}_alert_only",
                        features=row,
                        explanation=expl,
                    )
                    continue

                # 2. Safety rails check: immunity for PID 1, system processes, agent itself, allowlists
                is_immune, reason = self.safety.is_immune(pid, process_name=row.get("process_name"))
                if is_immune:
                    logger.info("[SAFETY RAILS] PID=%s is immune from containment (%s). Action suppressed.", pid, reason)
                    continue

                # 3. Rate limit & False-Positive Storm Panic Switch
                permitted, permit_reason = self.safety.check_containment_permitted(pid)
                if not permitted:
                    logger.warning("[SAFETY RAILS] Containment suppressed for PID=%s: %s", pid, permit_reason)
                    if self.safety.panic_switch_tripped:
                        self.logger.log("storm_panic_switch_tripped", pid=pid, reason=permit_reason)
                    continue

                self.logger.log("alert_critical", pid=pid, risk_ewma=ewma, mode=active_mode, evidence=row, explanation=expl)
                if self.dry_run:
                    logger.info("[DRY-RUN] Would contain PID=%s with policy=%s", pid, self.rollback_policy.value)
                    self._contained_pids.add(pid)
                    self.telemetry.record(
                        pid=pid,
                        mode=active_mode,
                        risk_score=ewma,
                        risk_level="CRITICAL",
                        action="dry_run",
                        features=row,
                        explanation=expl,
                    )
                    continue

                target = self.protection.get_target_for_path(self.watch_path) if hasattr(self, "protection") else None
                rollback_available = target.rollback_available if target else True
                rollback_reason = target.reason if target else None

                result = contain(
                    pid, self.overlay_upperdir, self.overlay_workdir,
                    self.quarantine_dir, policy=self.rollback_policy,
                    control_dir=self.control_dir, evidence=row,
                    use_freeze=self.use_freeze,
                    rollback_available=rollback_available,
                    rollback_reason=rollback_reason,
                )
                self._contained_pids.add(pid)
                if result.awaiting_manual_decision:
                    self._awaiting_manual.add(pid)
                self._log_containment_result(pid, result)
                self.telemetry.record(
                    pid=pid,
                    mode=active_mode,
                    risk_score=ewma,
                    risk_level="CRITICAL",
                    action="contained" if result.rolled_back or result.frozen_ts else "quarantined",
                    features=row,
                    explanation=expl,
                )

                # 4. Persist runtime state
                status = "awaiting_manual" if result.awaiting_manual_decision else ("quarantined" if result.rolled_back else "frozen")
                self.state_mgr.record_containment(
                    pid=pid,
                    policy=self.rollback_policy.value,
                    status=status,
                    evidence=row,
                    quarantine_path=result.quarantine_path,
                    overlay_upper=self.overlay_upperdir,
                    overlay_work=self.overlay_workdir,
                )

    def _poll_manual_decisions(self):
        resolved = []
        for pid in list(self._awaiting_manual):
            decision = check_manual_decision(self.control_dir, pid)
            if decision is None:
                continue
            result = resolve_manual_decision(
                pid, decision, self.overlay_upperdir, self.overlay_workdir,
                self.quarantine_dir, self.control_dir,
            )
            self._log_containment_result(pid, result)
            self.logger.log("manual_decision_applied", pid=pid, decision=decision)
            self.state_mgr.record_resolution(pid, decision)
            resolved.append(pid)
        for pid in resolved:
            self._awaiting_manual.discard(pid)

    def run_forever(self):
        if self.tier0:
            self.tier0.start()
        logger.info(
            "AdaptShield Daemon active. Mode: %s | Policy: %s | Tier-1: %s | Watch: %s",
            self.config.mode,
            self.rollback_policy.value,
            "ENABLED" if self.tier1_available else "DISABLED (Tier-0-only)",
            self.watch_path,
        )
        try:
            while True:
                if self.tier1:
                    self.tier1.poll(timeout_ms=int(self.window_seconds * 1000))
                    self.aggregator.add_tier1_events(self.tier1.drain_events())
                else:
                    time.sleep(self.window_seconds)

                snapshot = self.tier0.snapshot_features() if self.tier0 else {}
                self._maybe_escalate(snapshot)
                rows = self.aggregator.build_rows(snapshot)
                self._classify_and_score(rows)
                self._poll_manual_decisions()
        except KeyboardInterrupt:
            logger.info("Daemon interrupted by operator.")
        finally:
            self.stop(thaw_processes=False)

    def stop(self, thaw_processes: bool = False):
        """Clean shutdown handler."""
        logger.info("Stopping AdaptShieldDaemon...")
        if self.tier0:
            try:
                self.tier0.stop()
            except Exception:
                pass
        if self.tier1:
            try:
                self.tier1.stop()
            except Exception:
                pass
        if hasattr(self, "protection"):
            try:
                self.protection.cleanup_all(unmount=True)
            except Exception:
                pass
        if hasattr(self, "telemetry"):
            try:
                self.telemetry.flush()
                self.telemetry.close()
            except Exception:
                pass
        if thaw_processes:
            for pid in list(self._contained_pids):
                try:
                    unfreeze_pid(pid)
                except Exception:
                    pass
        logger.info("AdaptShieldDaemon stopped cleanly.")

    def reload_config(self, new_config: AdaptShieldConfig | None = None):
        """Hot reload configuration and active model atomically."""
        logger.info("[RELOAD] Initiating hot reload...")
        if new_config is None:
            new_config = load_config()
        self.config = new_config

        # 1. Update mode manager
        self.mode_mgr.reload_config(new_config)

        # 2. Update safety rails
        self.safety = SafetyRails(new_config)

        # 3. Update risk scorer parameters
        self.risk_scorer.alpha = new_config.detection.ewma_alpha
        self.risk_scorer.watch_threshold = new_config.detection.thresholds.elevated
        self.risk_scorer.suspect_threshold = new_config.detection.thresholds.suspicious
        self.risk_scorer.critical_threshold = new_config.detection.thresholds.critical
        self.risk_scorer.critical_confirm_windows = new_config.detection.consecutive_windows_for_critical

        # 4. Atomic model reload
        try:
            new_clf, new_meta = select_classifier(new_config)
            self.classifier = new_clf
            self.classifier_metadata = new_meta
            logger.info("[RELOAD] Model successfully reloaded: %s", new_meta.get("name"))
        except Exception as e:
            logger.warning("[RELOAD FAILED] Could not reload new model (%s). Keeping active model %s.", e, self.classifier_metadata.get("name"))

        logger.info("[RELOAD] Hot reload completed successfully.")


def main():
    ap = argparse.ArgumentParser(description="AdaptShield Autonomous Endpoint Daemon")
    ap.add_argument("--config", default=None, help="Path to config YAML (default: /etc/adaptshield/config.yaml)")
    ap.add_argument("--watch", default=None, help="Path to monitor (overrides config)")
    ap.add_argument("--overlay-upper", default=None, help="Overlay upper directory")
    ap.add_argument("--overlay-work", default=None, help="Overlay work directory")
    ap.add_argument("--quarantine-dir", default=None, help="Quarantine directory")
    ap.add_argument("--control-dir", default=None, help="Control directory for manual decisions")
    ap.add_argument("--rollback-policy", default=None, choices=["none", "immediate", "manual"])
    ap.add_argument("--window", type=float, default=None)
    ap.add_argument("--theta0", type=float, default=None)
    ap.add_argument("--classifier", default=None, choices=["rule_based", "random_forest", "xgboost"])
    ap.add_argument("--model-path", default=None, help="Path to saved joblib model")
    ap.add_argument("--log", default=None, help="Path to JSONL alert log")
    ap.add_argument("--no-escalation", action="store_true")
    ap.add_argument("--no-tier1", action="store_true")
    ap.add_argument("--no-smoothing", action="store_true")
    ap.add_argument("--kill-instead-of-freeze", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="Log actions without executing containment")
    args = ap.parse_args()

    # Load configuration from file or default
    cfg = load_config(args.config)
    setup_logging(
        level=cfg.logging.level,
        log_file=cfg.logging.file,
        max_bytes=cfg.logging.max_bytes,
        backup_count=cfg.logging.backup_count,
        use_journald=cfg.logging.use_journald,
    )

    # Determine parameter values: CLI overrides config, config overrides defaults
    watch_path = args.watch or (cfg.watch.paths[0] if cfg.watch.paths else "/home")
    window = args.window if args.window is not None else cfg.detection.window_seconds
    theta0 = args.theta0 if args.theta0 is not None else cfg.detection.theta0
    classifier_name = args.classifier or cfg.classifier.model_name
    overlay_upper = args.overlay_upper or os.path.join(cfg.response.quarantine_dir, "upper")
    overlay_work = args.overlay_work or os.path.join(cfg.response.quarantine_dir, "work")
    quarantine_dir = args.quarantine_dir or cfg.response.quarantine_dir
    control_dir = args.control_dir or cfg.response.control_dir
    log_path = args.log or cfg.logging.alert_file
    policy_str = args.rollback_policy or cfg.response.policy
    rollback_policy = RollbackPolicy(policy_str)
    use_escalation = False if args.no_escalation else cfg.detection.use_escalation
    use_tier1 = False if args.no_tier1 else cfg.detection.use_tier1
    use_smoothing = False if args.no_smoothing else cfg.detection.use_risk_smoothing
    use_freeze = False if args.kill_instead_of_freeze else cfg.response.use_freeze

    daemon = AdaptShieldDaemon(
        watch_path=watch_path,
        window_seconds=window,
        theta0=theta0,
        classifier_name=classifier_name,
        overlay_upperdir=overlay_upper,
        overlay_workdir=overlay_work,
        quarantine_dir=quarantine_dir,
        control_dir=control_dir,
        log_path=log_path,
        rollback_policy=rollback_policy,
        use_escalation=use_escalation,
        use_tier1=use_tier1,
        use_risk_smoothing=use_smoothing,
        use_freeze=use_freeze,
        model_path=args.model_path or cfg.classifier.model_path,
        config=cfg,
        dry_run=args.dry_run,
    )
    daemon.run_forever()


if __name__ == "__main__":
    main()
