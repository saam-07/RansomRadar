"""
Auto-seed demo data on first startup.
"""

from __future__ import annotations

import datetime
import json
import uuid
import logging
from sqlalchemy.orm import Session
from backend.app.db.session import SessionLocal
from backend.app.db.models import ScenarioRunRecord, AlertRecord, ContainmentRecord

logger = logging.getLogger(__name__)


def seed_demo_data() -> None:
    """Seeds historical scenario runs and alerts if DB has no runs."""
    db: Session = SessionLocal()
    try:
        run_count = db.query(ScenarioRunRecord).count()
        if run_count > 0:
            return  # Already seeded or has user runs

        now = datetime.datetime.utcnow()

        # 1. Normal Workday Run (Clean, no containments)
        run_workday = ScenarioRunRecord(
            id=str(uuid.uuid4()),
            scenario_name="normal_workday",
            detector="xgboost",
            policy="immediate",
            speed=20.0,
            seed=42,
            status="completed",
            started_at=now - datetime.timedelta(minutes=30),
            completed_at=now - datetime.timedelta(minutes=28),
            total_windows=18,
            distinct_pids=3,
            contained_pids=json.dumps([]),
            time_to_detect_windows=None,
            time_to_detect_seconds=None,
            wall_time_seconds=0.12,
            files_encrypted=0,
            files_restored=0,
            files_intact=300,
            panic_tripped=False,
            summary_json=json.dumps({
                "scenario": "normal_workday",
                "detector": "xgboost",
                "seed": 42,
                "total_windows": 18,
                "distinct_pids": 3,
                "contained_pids": [],
                "time_to_detect_windows": None,
                "time_to_detect_seconds": None,
                "wall_time_seconds": 0.12,
                "simulated": True,
            }),
        )
        db.add(run_workday)

        # 2. Nightly Backup Run (High IOPS benign, no false alarms)
        run_backup = ScenarioRunRecord(
            id=str(uuid.uuid4()),
            scenario_name="nightly_backup",
            detector="xgboost",
            policy="immediate",
            speed=20.0,
            seed=42,
            status="completed",
            started_at=now - datetime.timedelta(minutes=20),
            completed_at=now - datetime.timedelta(minutes=18),
            total_windows=22,
            distinct_pids=2,
            contained_pids=json.dumps([]),
            time_to_detect_windows=None,
            time_to_detect_seconds=None,
            wall_time_seconds=0.15,
            files_encrypted=0,
            files_restored=0,
            files_intact=300,
            panic_tripped=False,
            summary_json=json.dumps({
                "scenario": "nightly_backup",
                "detector": "xgboost",
                "seed": 42,
                "total_windows": 22,
                "distinct_pids": 2,
                "contained_pids": [],
                "time_to_detect_windows": None,
                "time_to_detect_seconds": None,
                "wall_time_seconds": 0.15,
                "simulated": True,
            }),
        )
        db.add(run_backup)

        # 3. Fast Ransomware Run (Rapid bulk encryption -> contained & rolled back)
        run_rw_id = str(uuid.uuid4())
        run_rw = ScenarioRunRecord(
            id=run_rw_id,
            scenario_name="fast_ransomware",
            detector="xgboost",
            policy="immediate",
            speed=20.0,
            seed=42,
            status="completed",
            started_at=now - datetime.timedelta(minutes=10),
            completed_at=now - datetime.timedelta(minutes=8),
            total_windows=16,
            distinct_pids=2,
            contained_pids=json.dumps([4099]),
            time_to_detect_windows=4,
            time_to_detect_seconds=8.0,
            wall_time_seconds=0.11,
            files_encrypted=55,
            files_restored=55,
            files_intact=245,
            panic_tripped=False,
            summary_json=json.dumps({
                "scenario": "fast_ransomware",
                "detector": "xgboost",
                "seed": 42,
                "total_windows": 16,
                "distinct_pids": 2,
                "contained_pids": [4099],
                "time_to_detect_windows": 4,
                "time_to_detect_seconds": 8.0,
                "wall_time_seconds": 0.11,
                "filesystem_status": {"intact": 245, "restored": 55, "encrypted": 0},
                "simulated": True,
            }),
        )
        db.add(run_rw)

        # Alert for fast ransomware run
        alert_id = str(uuid.uuid4())
        alert_rw = AlertRecord(
            id=alert_id,
            run_id=run_rw_id,
            timestamp=now - datetime.timedelta(minutes=9),
            pid=4099,
            process_name="locker_fast",
            risk_level="CRITICAL",
            ewma_score=0.912,
            model_name="xgboost",
            explanation_json=json.dumps({
                "classifier_name": "xgboost",
                "explanation_type": "tree_feature_contributions",
                "baseline_risk": 0.05,
                "predicted_risk": 0.98,
                "primary_contributing_feature": "entropy",
                "contributions": [
                    {"feature": "entropy", "contribution": 0.38, "value": 7.92},
                    {"feature": "write_read_ratio", "contribution": 0.25, "value": 85.0},
                    {"feature": "mod_rate", "contribution": 0.18, "value": 110.0},
                ],
                "summary": "Process exhibited high Shannon entropy (7.92), write/read ratio (85.0), and rapid file modification rate (110.0).",
                "data_source": "synthetic",
                "simulated": True,
            }),
            window_data_json=json.dumps({
                "pid": 4099,
                "process_name": "locker_fast",
                "entropy": 7.92,
                "write_read_ratio": 85.0,
                "mod_rate": 110.0,
                "dir_traversal_rate": 42.0,
                "renames_per_sec": 55.0,
                "timestamp": (now - datetime.timedelta(minutes=9)).isoformat(),
            }),
            status="confirmed",
            action_taken="freeze",
        )
        db.add(alert_rw)

        # Containment action
        cont_action = ContainmentRecord(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            pid=4099,
            action="freeze",
            policy="immediate",
            latency_ms=1.45,
            is_frozen=True,
            is_quarantined=True,
            is_rolled_back=True,
            timestamp=now - datetime.timedelta(minutes=9),
            details_json=json.dumps({
                "files_rolled_back": 55,
                "bytes_restored": 2883584,
                "simulated": True,
            }),
        )
        db.add(cont_action)

        db.commit()
        logger.info("Successfully seeded demo data (3 historical scenario runs, 1 critical alert).")
    except Exception as e:
        logger.error(f"Failed to seed demo data: {e}")
        db.rollback()
    finally:
        db.close()
