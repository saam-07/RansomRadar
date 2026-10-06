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
from typing import Optional

import pandas as pd

from .config import AdaptShieldConfig, load_config
from .detection.fanotify_ctypes import Fanotify
from .detection.tier0_watcher import Tier0Watcher, tier0_suspicion_score
from .detection.tier1_bridge import Tier1Tracer, is_tier1_available, get_tier1_status
from .detection.feature_aggregator import FeatureAggregator, FEATURE_COLUMNS
from .detection.risk_scorer import RiskScorer, RiskLevel
from .response.containment_manager import (
    ensure_cgroup_ready, contain, RollbackPolicy,
    check_manual_decision, resolve_manual_decision,
)
from .logging.logger import get_logger, setup_logging
from .logging.alert_logger import AlertLogger
from .ml.classifier import build_classifier
from .ml.registry import ModelRegistry

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

        # 1. Tier-0 Watcher (attempt initialization with fallback for non-Linux / sandbox)
        try:
            self.tier0 = Tier0Watcher(watch_path, window_seconds=window_seconds)
            self.tier0_available = True
        except Exception as e:
            logger.warning("Fanotify unavailable on %s (%s); running in mock/sandbox watcher mode.", watch_path, e)
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

        # 4. Classifier
        if model is not None:
            self.classifier = model
        elif model_path and os.path.exists(model_path):
            self.classifier = build_classifier(classifier_name).load(model_path)
        else:
            # Check model registry
            registry_dir = self.config.classifier.registry_dir
            if os.path.exists(registry_dir):
                try:
                    registry = ModelRegistry(registry_dir)
                    clf, manifest = registry.get_active_model()
                    self.classifier = clf
                    logger.info("Loaded active classifier '%s' from registry.", manifest.get("name"))
                except Exception as e:
                    logger.warning("Could not load active model from registry (%s); using default %s", e, classifier_name)
                    self.classifier = build_classifier(classifier_name)
            else:
                self.classifier = build_classifier(classifier_name)

        # 5. Risk Scorer
        self.risk_scorer = RiskScorer(
            alpha=self.config.detection.ewma_alpha,
            watch_threshold=self.config.detection.thresholds.elevated,
            suspect_threshold=self.config.detection.thresholds.suspicious,
            critical_threshold=self.config.detection.thresholds.critical,
            critical_confirm_windows=self.config.detection.consecutive_windows_for_critical,
        )

        # 6. Logger & Cgroups
        self.logger = AlertLogger(log_path)
        self._escalated_pids: set[int] = set()
        self._contained_pids: set[int] = set()
        self._awaiting_manual: set[int] = set()

        try:
            ensure_cgroup_ready()
        except Exception as e:
            logger.debug("cgroup v2 initialization skipped in userspace: %s", e)

    @classmethod
    def from_config(cls, cfg: AdaptShieldConfig | None = None, dry_run: bool = False) -> "AdaptShieldDaemon":
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
        # Drop non-feature metadata columns
        feature_df = df[[c for c in FEATURE_COLUMNS if c in df.columns]]
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
                self.logger.log("alert_critical", pid=pid, risk_ewma=ewma, evidence=row)
                if self.dry_run:
                    logger.info("[DRY-RUN] Would contain PID=%s with policy=%s", pid, self.rollback_policy.value)
                    self._contained_pids.add(pid)
                    continue

                result = contain(
                    pid, self.overlay_upperdir, self.overlay_workdir,
                    self.quarantine_dir, policy=self.rollback_policy,
                    control_dir=self.control_dir, evidence=row,
                    use_freeze=self.use_freeze,
                )
                self._contained_pids.add(pid)
                if result.awaiting_manual_decision:
                    self._awaiting_manual.add(pid)
                self._log_containment_result(pid, result)

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
            if self.tier0:
                self.tier0.stop()


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
