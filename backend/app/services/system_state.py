"""
System State Coordinator for AdaptShield Backend.
Manages the DetectionPipeline, active processes, running scenarios,
background training jobs, and persists events to the SQLite database.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Set

from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.schema import FEATURE_COLUMNS, SCHEMA_VERSION, validate_features
from adaptshield.ml.evaluate import extract_ransomware_prob
from adaptshield.ml.train import train_classifier
from adaptshield.ml.evaluate import evaluate_classifier
from backend.app.config import settings
from backend.app.core.bus import EventBus
from backend.app.core.pipeline import DetectionPipeline
from backend.app.core.response import SimulatedResponse
from backend.app.core.safety import SafetyRails
from backend.app.core.sources import SimulatedSource
from backend.app.db.session import SessionLocal
from backend.app.db.models import ScenarioRunRecord, AlertRecord, ContainmentRecord, TrainingJobRecord

logger = logging.getLogger(__name__)


class ScenarioTask:
    def __init__(
        self,
        run_id: str,
        scenario_name: str,
        detector: str,
        policy: str,
        speed: float,
        seed: int,
    ):
        self.run_id = run_id
        self.scenario_name = scenario_name
        self.detector = detector
        self.policy = policy
        self.speed = speed
        self.seed = seed
        self.status = "running"
        self.started_at = datetime.datetime.utcnow()
        self.completed_at: Optional[datetime.datetime] = None
        self.total_windows = 0
        self.distinct_pids: Set[int] = set()
        self.contained_pids: Set[int] = set()
        self.time_to_detect_windows: Optional[int] = None
        self.should_stop = False
        self.thread: Optional[threading.Thread] = None


class SystemStateManager:
    _instance: Optional["SystemStateManager"] = None

    def __init__(self):
        self.bus = EventBus()
        self.registry = ModelRegistry()
        self.safety_rails = SafetyRails(
            panic_distinct_pids=settings.pipeline.panic_storm_threshold,
        )
        self.response_engine = SimulatedResponse(
            default_policy=settings.pipeline.default_policy,
        )
        self.pipeline = DetectionPipeline(
            registry=self.registry,
            response_engine=self.response_engine,
            safety_rails=self.safety_rails,
            event_bus=self.bus,
            model_name=settings.pipeline.default_detector,
            default_policy=settings.pipeline.default_policy,
        )

        self.mode = settings.pipeline.default_mode  # simulated | live
        self.policy = settings.pipeline.default_policy  # immediate | manual | none

        # Active processes tracked in memory
        self.active_processes: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # Active running scenario task
        self.active_scenario: Optional[ScenarioTask] = None

        # Subscribe internal handler to bus events
        self._setup_event_listeners()

    @classmethod
    def get_instance(cls) -> "SystemStateManager":
        if cls._instance is None:
            cls._instance = SystemStateManager()
        return cls._instance

    def _setup_event_listeners(self) -> None:
        self.bus.subscribe("window_scored", self._on_window_scored)
        self.bus.subscribe("alert", self._on_alert)
        self.bus.subscribe("containment", self._on_containment)

    def _on_window_scored(self, event: Dict[str, Any]) -> None:
        pid = event.get("pid")
        if pid is None:
            return
        with self._lock:
            proc = self.active_processes.get(pid, {
                "pid": pid,
                "process_name": event.get("process_name", f"proc_{pid}"),
                "status": "normal",
                "is_frozen": False,
                "is_quarantined": False,
                "files_touched": 0,
                "files_encrypted": 0,
            })
            proc["risk_level"] = event.get("risk_level", "NORMAL")
            proc["ewma"] = event.get("ewma", 0.0)
            proc["probability"] = event.get("probability", 0.0)
            proc["label"] = event.get("label", "benign")
            proc["last_window_idx"] = event.get("window_idx", 0)
            proc["files_touched"] += int(event.get("mod_rate", 0))
            proc["files_encrypted"] += int(event.get("files_encrypted_now", 0))
            proc["updated_at"] = datetime.datetime.utcnow().isoformat()
            self.active_processes[pid] = proc

    def _on_alert(self, event: Dict[str, Any]) -> None:
        """Persists critical alert to SQLite."""
        try:
            alert_id = str(uuid.uuid4())
            pid = int(event.get("pid", 0))
            pname = str(event.get("process_name", f"proc_{pid}"))
            run_id = self.active_scenario.run_id if self.active_scenario else None

            db = SessionLocal()
            alert_rec = AlertRecord(
                id=alert_id,
                run_id=run_id,
                timestamp=datetime.datetime.utcnow(),
                pid=pid,
                process_name=pname,
                risk_level="CRITICAL",
                ewma_score=float(event.get("ewma", 0.0)),
                model_name=str(event.get("model_name", self.pipeline.model_name)),
                explanation_json=json.dumps(event.get("explanation", {})),
                window_data_json=json.dumps(event),
                status="active",
                action_taken="freeze" if self.policy == "immediate" else "pending_review",
            )
            db.add(alert_rec)
            db.commit()
            db.close()

            # Attach generated alert_id to event
            event["alert_id"] = alert_id
        except Exception as e:
            logger.error(f"Failed to persist alert: {e}")

    def _on_containment(self, event: Dict[str, Any]) -> None:
        """Persists containment action to SQLite."""
        try:
            pid = int(event.get("pid", 0))
            with self._lock:
                if pid in self.active_processes:
                    self.active_processes[pid]["is_frozen"] = bool(event.get("is_frozen", False))
                    self.active_processes[pid]["status"] = "frozen" if event.get("is_frozen") else "normal"

            db = SessionLocal()
            action_rec = ContainmentRecord(
                id=str(uuid.uuid4()),
                pid=pid,
                action=str(event.get("action", "freeze")),
                policy=self.policy,
                latency_ms=float(event.get("latency_ms", 0.0)),
                is_frozen=bool(event.get("is_frozen", False)),
                is_quarantined=bool(event.get("is_quarantined", False)),
                is_rolled_back=bool(event.get("is_rolled_back", False)),
                timestamp=datetime.datetime.utcnow(),
                details_json=json.dumps(event),
            )
            db.add(action_rec)
            db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Failed to persist containment action: {e}")

    # --- Scenario Execution ---

    def start_scenario(
        self,
        scenario_name: str,
        detector: Optional[str] = None,
        policy: Optional[str] = None,
        speed: float = 1.0,
        seed: int = 42,
    ) -> str:
        """Starts a background scenario run."""
        if self.active_scenario and self.active_scenario.status == "running":
            raise RuntimeError(f"Scenario '{self.active_scenario.scenario_name}' is already running")

        run_id = str(uuid.uuid4())
        chosen_detector = detector or self.pipeline.model_name
        chosen_policy = policy or self.policy

        # Update pipeline detector and policy if requested
        if detector and detector != self.pipeline.model_name:
            self.set_detector(detector)
        if policy and policy != self.policy:
            self.set_policy(policy)

        # Clear processes and reset response engine for fresh scenario
        with self._lock:
            self.active_processes.clear()
        self.response_engine = SimulatedResponse(default_policy=chosen_policy)
        self.safety_rails.reset_storm_state()
        self.pipeline.response_engine = self.response_engine
        self.pipeline.safety_rails = self.safety_rails
        self.pipeline.scorers.clear()

        task = ScenarioTask(
            run_id=run_id,
            scenario_name=scenario_name,
            detector=chosen_detector,
            policy=chosen_policy,
            speed=speed,
            seed=seed,
        )
        self.active_scenario = task

        # Create record in DB
        db = SessionLocal()
        run_record = ScenarioRunRecord(
            id=run_id,
            scenario_name=scenario_name,
            detector=chosen_detector,
            policy=chosen_policy,
            speed=speed,
            seed=seed,
            status="running",
            started_at=task.started_at,
        )
        db.add(run_record)
        db.commit()
        db.close()

        # Run in background thread
        thread = threading.Thread(target=self._run_scenario_thread, args=(task,), daemon=True)
        task.thread = thread
        thread.start()

        return run_id

    def stop_scenario(self) -> bool:
        """Signals active scenario to stop."""
        if self.active_scenario and self.active_scenario.status == "running":
            self.active_scenario.should_stop = True
            return True
        return False

    def _run_scenario_thread(self, task: ScenarioTask) -> None:
        source = SimulatedSource(scenario=task.scenario_name, seed=task.seed, speed=task.speed)
        self.bus.publish("scenario_state", {
            "state": "started",
            "run_id": task.run_id,
            "scenario": task.scenario_name,
            "seed": task.seed,
            "speed": task.speed,
            "detector": task.detector,
            "policy": task.policy,
            "simulated": True,
        })

        t_start = time.perf_counter()
        try:
            # Run stream
            for win in source.stream_all(sleep_delay=True):
                if task.should_stop:
                    task.status = "stopped"
                    break

                task.total_windows += 1
                pid = int(win["pid"])
                task.distinct_pids.add(pid)

                res = self.pipeline.process_window(win)
                cont = res.get("containment")
                if cont and cont.get("action") == "freeze" and cont.get("is_frozen"):
                    if pid not in task.contained_pids:
                        task.contained_pids.add(pid)
                        if task.time_to_detect_windows is None:
                            task.time_to_detect_windows = win.get("window_idx")

            if task.status != "stopped":
                task.status = "completed"

        except Exception as e:
            logger.error(f"Error executing scenario {task.scenario_name}: {e}")
            task.status = "failed"

        task.completed_at = datetime.datetime.utcnow()
        wall_time = round(time.perf_counter() - t_start, 3)

        fs_summary = self.response_engine.get_filesystem_summary()
        status_counts = fs_summary.get("status_counts", {})
        encrypted_cnt = status_counts.get("encrypted", 0)
        restored_cnt = status_counts.get("restored", 0)
        intact_cnt = status_counts.get("intact", 300)

        summary_payload = {
            "run_id": task.run_id,
            "scenario": task.scenario_name,
            "detector": task.detector,
            "policy": task.policy,
            "seed": task.seed,
            "speed": task.speed,
            "total_windows": task.total_windows,
            "distinct_pids": len(task.distinct_pids),
            "contained_pids": sorted(list(task.contained_pids)),
            "time_to_detect_windows": task.time_to_detect_windows,
            "time_to_detect_seconds": (task.time_to_detect_windows * 2.0) if task.time_to_detect_windows is not None else None,
            "wall_time_seconds": wall_time,
            "files_encrypted": encrypted_cnt,
            "files_restored": restored_cnt,
            "files_intact": intact_cnt,
            "panic_tripped": self.safety_rails.panic_tripped,
            "simulated": True,
        }

        # Update DB record
        try:
            db = SessionLocal()
            record = db.query(ScenarioRunRecord).filter(ScenarioRunRecord.id == task.run_id).first()
            if record:
                record.status = task.status
                record.completed_at = task.completed_at
                record.total_windows = task.total_windows
                record.distinct_pids = len(task.distinct_pids)
                record.contained_pids = json.dumps(sorted(list(task.contained_pids)))
                record.time_to_detect_windows = task.time_to_detect_windows
                record.time_to_detect_seconds = summary_payload["time_to_detect_seconds"]
                record.wall_time_seconds = wall_time
                record.files_encrypted = encrypted_cnt
                record.files_restored = restored_cnt
                record.files_intact = intact_cnt
                record.panic_tripped = self.safety_rails.panic_tripped
                record.summary_json = json.dumps(summary_payload)
                db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Failed to update scenario run record in DB: {e}")

        self.bus.publish("scenario_state", {
            "state": task.status,
            "run_id": task.run_id,
            "summary": summary_payload,
            "simulated": True,
        })

    # --- Controls ---

    def set_detector(self, name: str) -> None:
        self.pipeline.set_detector(name)

    def set_policy(self, policy: str) -> None:
        if policy not in ("immediate", "manual", "none"):
            raise ValueError(f"Unknown policy: {policy}. Must be 'immediate', 'manual', or 'none'.")
        self.policy = policy
        self.response_engine.default_policy = policy
        self.pipeline.default_policy = policy

    def release_process(self, pid: int, reason: str = "Operator override") -> Dict[str, Any]:
        result = self.response_engine.unfreeze(pid)
        with self._lock:
            if pid in self.active_processes:
                self.active_processes[pid]["is_frozen"] = False
                self.active_processes[pid]["status"] = "normal"

        self.bus.publish("containment", {
            "pid": pid,
            "action": "release",
            "is_frozen": False,
            "reason": reason,
            "simulated": True,
        })
        return result

    def confirm_process(self, pid: int, reason: str = "Operator confirmed threat") -> Dict[str, Any]:
        result = self.response_engine.kill(pid)
        with self._lock:
            if pid in self.active_processes:
                self.active_processes[pid]["status"] = "killed"

        self.bus.publish("containment", {
            "pid": pid,
            "action": "confirm",
            "is_killed": True,
            "reason": reason,
            "simulated": True,
        })
        return result

    # --- Background Model Training ---

    def start_training_job(
        self,
        classifier_type: str,
        model_name: Optional[str] = None,
        hyperparameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        job_id = str(uuid.uuid4())
        name = model_name or f"{classifier_type}_{int(time.time())}"
        hyperparameters = hyperparameters or {}

        db = SessionLocal()
        job_rec = TrainingJobRecord(
            id=job_id,
            model_name=name,
            classifier_type=classifier_type,
            status="queued",
            progress=0.0,
            hyperparameters_json=json.dumps(hyperparameters),
        )
        db.add(job_rec)
        db.commit()
        db.close()

        # Launch training in background thread
        thread = threading.Thread(
            target=self._run_training_job,
            args=(job_id, name, classifier_type, hyperparameters),
            daemon=True,
        )
        thread.start()
        return job_id

    def _run_training_job(
        self,
        job_id: str,
        name: str,
        classifier_type: str,
        hyperparameters: Dict[str, Any],
    ) -> None:
        db = SessionLocal()
        try:
            job = db.query(TrainingJobRecord).filter(TrainingJobRecord.id == job_id).first()
            if job:
                job.status = "running"
                job.progress = 0.2
                db.commit()

            import pandas as pd
            from pathlib import Path
            repo_root = Path(__file__).resolve().parent.parent.parent.parent
            train_df = pd.read_csv(repo_root / "data" / "raw" / "traces_train.csv")
            val_df = pd.read_csv(repo_root / "data" / "raw" / "traces_val.csv")
            test_df = pd.read_csv(repo_root / "data" / "raw" / "traces_test.csv")
            hard_test_df = pd.read_csv(repo_root / "data" / "raw" / "traces_hard_test.csv")

            if job:
                job.progress = 0.5
                db.commit()

            model = train_classifier(
                classifier_name=classifier_type,
                train_df=train_df,
                columns=FEATURE_COLUMNS,
                **hyperparameters,
            )

            if job:
                job.progress = 0.8
                db.commit()

            eval_metrics = evaluate_classifier(
                clf=model,
                test_df=test_df,
                hard_test_df=hard_test_df,
            )

            # Register model
            self.registry.register_model(
                name=name,
                classifier=model,
                feature_columns=FEATURE_COLUMNS,
                metrics=eval_metrics,
                data_source="synthetic",
            )

            if job:
                job.status = "completed"
                job.progress = 1.0
                job.completed_at = datetime.datetime.utcnow()
                job.metrics_json = json.dumps(eval_metrics)
                db.commit()

        except Exception as e:
            logger.error(f"Training job {job_id} failed: {e}")
            if job:
                job.status = "failed"
                job.error_message = str(e)
                job.completed_at = datetime.datetime.utcnow()
                db.commit()
        finally:
            db.close()
