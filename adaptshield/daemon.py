"""
AdaptShield daemon -- the full pipeline described in roadmap Sec 2.1.

Run as root (needed for fanotify FAN_REPORT_PID, eBPF kprobes, and cgroups):
    sudo .venv/bin/python -m adaptshield.daemon \
        --watch /mnt/testfs_ext4 \
        --overlay-upper /mnt/testfs_ext4/.overlay_upper \
        --overlay-work /mnt/testfs_ext4/.overlay_work \
        --quarantine-dir /mnt/testfs_ext4/.quarantine \
        --rollback-policy immediate \
        --window 2.0

--rollback-policy controls what happens at CRITICAL risk:
    none      (default) -- freeze only, no rollback (matches the ONLY
               behavior the previous version of this file had)
    immediate -- freeze, quarantine touched files, roll back the overlay,
               kill the process. Filesystem state is genuinely restored.
    manual    -- freeze, then wait for an operator decision via
               containment_cli.py (release = unfreeze / confirm = rollback+kill)
"""
import argparse
import time

import pandas as pd

from .tier0_watcher import Tier0Watcher, tier0_suspicion_score
from .tier1_bridge import Tier1Tracer
from .feature_aggregator import FeatureAggregator, FEATURE_COLUMNS
from .classifier import build_classifier
from .risk_scorer import RiskScorer, RiskLevel
from .containment_manager import (
    ensure_cgroup_ready, contain, RollbackPolicy,
    check_manual_decision, resolve_manual_decision,
)
from .alert_logger import AlertLogger


class AdaptShieldDaemon:
    def __init__(self, watch_path: str, window_seconds: float, theta0: float,
                 classifier_name: str, overlay_upperdir: str, overlay_workdir: str,
                 quarantine_dir: str, control_dir: str,
                 log_path: str, rollback_policy: RollbackPolicy = RollbackPolicy.NONE,
                 use_escalation: bool = True,
                 use_tier1: bool = True, use_risk_smoothing: bool = True,
                 use_freeze: bool = True, model=None, model_path: str | None = None):
        self.tier0 = Tier0Watcher(watch_path, window_seconds=window_seconds)
        self.tier1 = Tier1Tracer() if use_tier1 else None
        self.aggregator = FeatureAggregator(window_seconds=window_seconds)
        if model is not None:
            self.classifier = model
        elif model_path and os.path.exists(model_path):
            self.classifier = build_classifier(classifier_name).load(model_path)
        else:
            self.classifier = build_classifier(classifier_name)
        self.risk_scorer = RiskScorer()

        self.logger = AlertLogger(log_path)
        self.window_seconds = window_seconds
        self.theta0 = theta0
        self.overlay_upperdir = overlay_upperdir
        self.overlay_workdir = overlay_workdir
        self.quarantine_dir = quarantine_dir
        self.control_dir = control_dir
        self.rollback_policy = rollback_policy
        self.use_escalation = use_escalation
        self.use_risk_smoothing = use_risk_smoothing
        self.use_freeze = use_freeze
        self._escalated_pids: set[int] = set()
        self._contained_pids: set[int] = set()
        self._awaiting_manual: set[int] = set()
        ensure_cgroup_ready()

    def _maybe_escalate(self, tier0_snapshot: dict):
        if not (self.use_escalation and self.tier1):
            return
        for pid, feats in tier0_snapshot.items():
            score = tier0_suspicion_score(feats)
            if score >= self.theta0 and pid not in self._escalated_pids:
                t_decide = time.monotonic()
                self.tier1.escalate(pid)
                t_active = time.monotonic()
                self._escalated_pids.add(pid)
                self.logger.log("escalation", pid=pid, tier0_score=score,
                                 escalation_latency_s=t_active - t_decide)

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
        proba = self.classifier.predict_proba(df)
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
                self.logger.log("alert_critical", pid=pid, risk_ewma=ewma,
                                 evidence=row)
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
        """Checks every pid currently frozen-and-waiting for an operator
        decision written via containment_cli.py, and acts on it as soon
        as one appears. This is what makes MANUAL policy actually
        reversible at the process level -- 'release' truly resumes the
        frozen process exactly where it paused."""
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
        self.tier0.start()
        try:
            while True:
                if self.tier1:
                    self.tier1.poll(timeout_ms=int(self.window_seconds * 1000))
                    self.aggregator.add_tier1_events(self.tier1.drain_events())
                else:
                    time.sleep(self.window_seconds)

                snapshot = self.tier0.snapshot_features()
                self._maybe_escalate(snapshot)
                rows = self.aggregator.build_rows(snapshot)
                self._classify_and_score(rows)
                self._poll_manual_decisions()
        except KeyboardInterrupt:
            pass
        finally:
            self.tier0.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", required=True, help="path to monitor, e.g. /mnt/testfs_ext4")
    ap.add_argument("--overlay-upper", required=True, help="overlayfs upperdir for damage diff")
    ap.add_argument("--overlay-work", required=True,
                     help="overlayfs workdir (required by the kernel alongside upperdir; "
                          "wiped together with upperdir on rollback)")
    ap.add_argument("--quarantine-dir", required=True,
                     help="where quarantined (copied) files are preserved before rollback")
    ap.add_argument("--control-dir", default="results/raw/control",
                     help="directory for manual-decision files, see containment_cli.py")
    ap.add_argument("--rollback-policy", default="none",
                     choices=["none", "immediate", "manual"],
                     help="none=freeze only (old default behavior); "
                          "immediate=freeze+quarantine+rollback+kill; "
                          "manual=freeze+wait for containment_cli.py decision")
    ap.add_argument("--window", type=float, default=2.0)
    ap.add_argument("--theta0", type=float, default=0.5)
    ap.add_argument("--classifier", default="xgboost",
                     choices=["rule_based", "random_forest", "xgboost"])
    ap.add_argument("--model-path", default=None,
                     help="path to saved joblib model (e.g. results/processed/xgb_model.joblib)")
    ap.add_argument("--log", default="results/raw/live_alerts.jsonl")
    ap.add_argument("--no-escalation", action="store_true",
                     help="ablation: always run Tier 1 (baseline 2)")
    ap.add_argument("--no-tier1", action="store_true",
                     help="ablation: Tier-0 features only (baseline 3)")
    ap.add_argument("--no-smoothing", action="store_true",
                     help="ablation: disable EWMA risk smoothing")
    ap.add_argument("--kill-instead-of-freeze", action="store_true",
                     help="ablation: irreversible containment baseline -- "
                          "skips freeze entirely, kills immediately, no "
                          "rollback possible (for comparison against the "
                          "reversible policies above)")
    args = ap.parse_args()

    daemon = AdaptShieldDaemon(
        watch_path=args.watch,
        window_seconds=args.window,
        theta0=args.theta0,
        classifier_name=args.classifier,
        overlay_upperdir=args.overlay_upper,
        overlay_workdir=args.overlay_work,
        quarantine_dir=args.quarantine_dir,
        control_dir=args.control_dir,
        log_path=args.log,
        rollback_policy=RollbackPolicy(args.rollback_policy),
        use_escalation=not args.no_escalation,
        use_tier1=not args.no_tier1,
        use_risk_smoothing=not args.no_smoothing,
        use_freeze=not args.kill_instead_of_freeze,
        model_path=args.model_path,
    )
    daemon.run_forever()



if __name__ == "__main__":
    main()
