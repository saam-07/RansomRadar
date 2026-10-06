"""
SQLAlchemy models for AdaptShield persistence.
"""

from __future__ import annotations

import datetime
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from backend.app.db.session import Base


class SchemaVersion(Base):
    __tablename__ = "schema_version"

    version = Column(Integer, primary_key=True)
    description = Column(String(255), nullable=False)
    applied_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class ScenarioRunRecord(Base):
    __tablename__ = "scenario_runs"

    id = Column(String(64), primary_key=True)
    scenario_name = Column(String(128), nullable=False)
    detector = Column(String(64), nullable=False)
    policy = Column(String(32), nullable=False, default="immediate")
    speed = Column(Float, nullable=False, default=1.0)
    seed = Column(Integer, nullable=False, default=42)
    status = Column(String(32), nullable=False, default="running")  # running, completed, stopped, failed
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    total_windows = Column(Integer, default=0, nullable=False)
    distinct_pids = Column(Integer, default=0, nullable=False)
    contained_pids = Column(Text, default="[]", nullable=False)  # JSON string
    time_to_detect_windows = Column(Integer, nullable=True)
    time_to_detect_seconds = Column(Float, nullable=True)
    wall_time_seconds = Column(Float, nullable=True)
    files_encrypted = Column(Integer, default=0, nullable=False)
    files_restored = Column(Integer, default=0, nullable=False)
    files_intact = Column(Integer, default=0, nullable=False)
    panic_tripped = Column(Boolean, default=False, nullable=False)
    summary_json = Column(Text, default="{}", nullable=False)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True)
    run_id = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    pid = Column(Integer, nullable=False)
    process_name = Column(String(128), nullable=False)
    risk_level = Column(String(32), nullable=False, default="CRITICAL")
    ewma_score = Column(Float, nullable=False, default=0.0)
    model_name = Column(String(64), nullable=False)
    explanation_json = Column(Text, default="{}", nullable=False)
    window_data_json = Column(Text, default="{}", nullable=False)
    status = Column(String(32), default="active", nullable=False)  # active, released, confirmed
    action_taken = Column(String(32), default="freeze", nullable=False)


class ContainmentRecord(Base):
    __tablename__ = "containment_actions"

    id = Column(String(64), primary_key=True)
    alert_id = Column(String(64), nullable=True)
    pid = Column(Integer, nullable=False)
    action = Column(String(32), nullable=False)  # freeze, quarantine, rollback, release, confirm, kill
    policy = Column(String(32), nullable=False, default="immediate")
    latency_ms = Column(Float, default=0.0, nullable=False)
    is_frozen = Column(Boolean, default=False, nullable=False)
    is_quarantined = Column(Boolean, default=False, nullable=False)
    is_rolled_back = Column(Boolean, default=False, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    details_json = Column(Text, default="{}", nullable=False)


class TrainingJobRecord(Base):
    __tablename__ = "training_jobs"

    id = Column(String(64), primary_key=True)
    model_name = Column(String(128), nullable=False)
    classifier_type = Column(String(64), nullable=False)
    status = Column(String(32), default="queued", nullable=False)  # queued, running, completed, failed
    progress = Column(Float, default=0.0, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    hyperparameters_json = Column(Text, default="{}", nullable=False)
    metrics_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
