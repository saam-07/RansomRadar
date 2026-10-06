"""
AdaptShield Detection & Containment Pipeline
============================================
Coordinates the end-to-end dataflow:
Feature Rows -> Feature Schema Validation -> Active Classifier ->
Per-PID RiskScorer -> Safety Rails -> ResponseEngine -> EventBus

Guarantees independent containment state per process PID.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.schema import validate_features
from adaptshield.ml.evaluate import extract_ransomware_prob
from adaptshield.risk_scorer import RiskLevel, RiskScorer
from backend.app.core.bus import EventBus
from backend.app.core.explain import explain_alert
from backend.app.core.response import ResponseEngine, SimulatedResponse
from backend.app.core.safety import SafetyRails
from backend.app.core.sources import EventSource, SimulatedSource


class DetectionPipeline:
    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        response_engine: Optional[ResponseEngine] = None,
        safety_rails: Optional[SafetyRails] = None,
        event_bus: Optional[EventBus] = None,
        model_name: Optional[str] = None,
        default_policy: str = "immediate",
    ):
        self.registry = registry or ModelRegistry()
        self.response_engine = response_engine or SimulatedResponse(default_policy=default_policy)
        self.safety_rails = safety_rails or SafetyRails()
        self.event_bus = event_bus or EventBus()
        self.default_policy = default_policy

        # Load active or specified detector
        if model_name:
            self.classifier, self.active_manifest = self.registry.load_model(model_name)
            self.model_name = model_name
        else:
            self.classifier, self.active_manifest = self.registry.get_active_model()
            self.model_name = self.active_manifest.get("name", "xgboost")

        self.feature_columns = self.active_manifest.get("feature_columns")

        # Independent RiskScorer instances per PID to prevent state bleed
        self.scorers: Dict[int, RiskScorer] = {}

    def get_scorer_for_pid(self, pid: int) -> RiskScorer:
        if pid not in self.scorers:
            self.scorers[pid] = RiskScorer(alpha=0.4, critical_confirm_windows=2)
        return self.scorers[pid]

    def set_detector(self, name: str) -> None:
        """Dynamically switches active classifier model."""
        self.classifier, self.active_manifest = self.registry.load_model(name)
        self.model_name = name
        self.feature_columns = self.active_manifest.get("feature_columns")
        self.event_bus.publish("model_switched", {"model_name": name, "manifest": self.active_manifest})

    def process_window(self, window_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes pipeline on a single evaluation window.
        """
        pid = int(window_data.get("pid", 1000))
        pname = str(window_data.get("process_name", f"proc_{pid}"))
        label = str(window_data.get("label", "benign"))
        mod_rate = float(window_data.get("mod_rate", 0.0))
        w_idx = int(window_data.get("window_idx", 0))

        # 1. Feature schema validation and cleaning
        X_clean = validate_features(window_data, expected_columns=self.feature_columns)

        # 2. Classifier inference
        prob_rw = float(extract_ransomware_prob(self.classifier, X_clean)[0])

        # 3. Stateful EWMA risk scoring per PID
        scorer = self.get_scorer_for_pid(pid)
        risk_level = scorer.update(pid, prob_rw)
        ewma_score = scorer.get_ewma(pid)

        # 4. Record virtual damage if simulated response engine
        damage_occurred = []
        if isinstance(self.response_engine, SimulatedResponse):
            is_rw_behavior = (label == "ransomware")
            damage_occurred = self.response_engine.record_process_activity(
                pid=pid,
                mod_rate=mod_rate,
                is_ransomware=is_rw_behavior,
            )

        # Publish window scored event
        window_event = {
            "pid": pid,
            "process_name": pname,
            "window_idx": w_idx,
            "probability": round(prob_rw, 4),
            "ewma": round(ewma_score, 4),
            "risk_level": risk_level.name,
            "label": label,
            "mod_rate": mod_rate,
            "files_encrypted_now": len(damage_occurred),
            "timestamp": window_data.get("timestamp"),
        }
        self.event_bus.publish("window_scored", window_event)

        containment_result: Optional[Dict[str, Any]] = None

        # 5. Risk escalation & Containment
        if risk_level == RiskLevel.CRITICAL:
            # Generate explanation for forensic alert
            explanation = explain_alert(
                classifier=self.classifier,
                feature_row=window_data,
                classifier_name=self.model_name,
            )

            alert_payload = {
                "pid": pid,
                "process_name": pname,
                "risk_level": "CRITICAL",
                "ewma": round(ewma_score, 4),
                "model_name": self.model_name,
                "explanation": explanation,
                "timestamp": window_data.get("timestamp"),
            }
            self.event_bus.publish("alert", alert_payload)

            # Check safety rails and panic switch
            can_contain, reason = self.safety_rails.check_can_contain(pid, pname)
            panic_tripped = self.safety_rails.record_critical_trigger(pid)

            if panic_tripped:
                self.event_bus.publish("panic_switch", {
                    "reason": "False-positive storm detected: distinct PIDs spiked to CRITICAL",
                    "action": "Mode dropped to monitor",
                })

            if can_contain and not panic_tripped:
                # Trigger per-PID containment
                containment_result = self.response_engine.freeze(pid)
                self.safety_rails.record_containment_action(pid)
                self.event_bus.publish("containment", containment_result)
            else:
                containment_result = {
                    "pid": pid,
                    "action": "blocked",
                    "reason": reason,
                    "simulated": True,
                }

        # Check auto-resolve timeouts on manual policy
        if isinstance(self.response_engine, SimulatedResponse):
            resolved = self.response_engine.check_auto_resolve()
            for r in resolved:
                self.event_bus.publish("auto_resolve", r)

        return {
            "window": window_event,
            "containment": containment_result,
            "risk_level": risk_level.name,
            "ewma": round(ewma_score, 4),
        }

    def run_scenario(
        self,
        scenario: str | Dict[str, Any],
        seed: int = 42,
        speed: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Executes a complete benchmark scenario and aggregates metrics.
        """
        source = SimulatedSource(scenario=scenario, seed=seed, speed=speed)
        scenario_id = source.scenario_config.get("id", "scenario")
        self.event_bus.publish("scenario_state", {"state": "started", "scenario": scenario_id, "seed": seed})

        total_windows = 0
        pids_seen = set()
        contained_pids = set()
        first_containment_window: Optional[int] = None

        t_start = time.perf_counter()

        for win in source.stream_all(sleep_delay=False):
            total_windows += 1
            pid = int(win["pid"])
            pids_seen.add(pid)

            res = self.process_window(win)
            cont = res.get("containment")
            if cont and cont.get("action") == "freeze" and cont.get("is_frozen"):
                if pid not in contained_pids:
                    contained_pids.add(pid)
                    if first_containment_window is None:
                        first_containment_window = win.get("window_idx")

        wall_time = round((time.perf_counter() - t_start), 3)

        fs_summary = {}
        if isinstance(self.response_engine, SimulatedResponse):
            fs_summary = self.response_engine.get_filesystem_summary()

        summary = {
            "scenario": scenario_id,
            "detector": self.model_name,
            "seed": seed,
            "total_windows": total_windows,
            "distinct_pids": len(pids_seen),
            "contained_pids": sorted(list(contained_pids)),
            "time_to_detect_windows": first_containment_window,
            "time_to_detect_seconds": (first_containment_window * 2.0) if first_containment_window is not None else None,
            "wall_time_seconds": wall_time,
            "filesystem_status": fs_summary.get("status_counts", {}),
            "panic_tripped": self.safety_rails.panic_tripped,
        }

        self.event_bus.publish("scenario_state", {"state": "completed", "summary": summary})
        return summary
