"""
Pydantic schemas for AdaptShield API requests and responses.
All simulated responses carry simulated=True.
All model responses carry data_source.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# --- Health & Status ---

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    simulated: bool = True


class StatusResponse(BaseModel):
    status: str = "running"
    mode: str = "simulated"  # simulated | live
    active_policy: str = "immediate"  # immediate | manual | none
    active_detector: str = "xgboost"
    active_manifest: Dict[str, Any] = Field(default_factory=dict)
    data_source: str = "synthetic"
    storm_panic: bool = False
    running_scenario: Optional[Dict[str, Any]] = None
    simulated: bool = True


class ControlRequest(BaseModel):
    mode: Optional[str] = None  # simulated | live
    policy: Optional[str] = None  # immediate | manual | none
    detector: Optional[str] = None
    reset_storm: Optional[bool] = None


class ControlResponse(BaseModel):
    success: bool = True
    message: str
    mode: str
    policy: str
    active_detector: str
    storm_panic: bool
    simulated: bool = True


# --- Processes ---

class ProcessItem(BaseModel):
    pid: int
    process_name: str
    cmdline: Optional[str] = None
    label: str = "benign"
    risk_level: str = "NORMAL"
    ewma: float = 0.0
    probability: float = 0.0
    status: str = "normal"  # normal, monitored, frozen, quarantined, killed
    is_frozen: bool = False
    is_quarantined: bool = False
    files_touched: int = 0
    files_encrypted: int = 0
    last_window_idx: int = 0
    updated_at: Optional[str] = None
    simulated: bool = True


class ProcessListResponse(BaseModel):
    processes: List[ProcessItem]
    total: int
    simulated: bool = True


# --- Alerts & Containment ---

class AlertItem(BaseModel):
    id: str
    run_id: Optional[str] = None
    timestamp: str
    pid: int
    process_name: str
    risk_level: str
    ewma_score: float
    model_name: str
    explanation: Dict[str, Any]
    window_data: Dict[str, Any]
    status: str  # active, released, confirmed
    action_taken: str
    simulated: bool = True


class AlertListResponse(BaseModel):
    alerts: List[AlertItem]
    total: int
    simulated: bool = True


class ContainmentActionRequest(BaseModel):
    pid: int
    action: str = "release"  # release | confirm | kill
    reason: Optional[str] = "Manual operator intervention"


class ContainmentActionResponse(BaseModel):
    pid: int
    action: str
    success: bool
    status: str
    message: str
    simulated: bool = True


# --- Scenarios ---

class ScenarioDefinition(BaseModel):
    id: str
    name: str
    description: str
    duration_windows: int
    processes_count: int
    family: str
    expected_outcome: str


class ScenarioRunRequest(BaseModel):
    scenario_name: str
    detector: Optional[str] = None
    policy: Optional[str] = None
    speed: Optional[float] = 1.0
    seed: Optional[int] = 42


class ScenarioRunResponse(BaseModel):
    run_id: str
    scenario_name: str
    detector: str
    policy: str
    speed: float
    seed: int
    status: str
    message: str
    simulated: bool = True


class ScenarioRunDetail(BaseModel):
    id: str
    scenario_name: str
    detector: str
    policy: str
    speed: float
    seed: int
    status: str
    started_at: str
    completed_at: Optional[str] = None
    total_windows: int = 0
    distinct_pids: int = 0
    contained_pids: List[int] = Field(default_factory=list)
    time_to_detect_windows: Optional[int] = None
    time_to_detect_seconds: Optional[float] = None
    wall_time_seconds: Optional[float] = None
    files_encrypted: int = 0
    files_restored: int = 0
    files_intact: int = 0
    panic_tripped: bool = False
    summary: Dict[str, Any] = Field(default_factory=dict)
    simulated: bool = True


# --- Datasets ---

class DatasetListResponse(BaseModel):
    generator_version: str
    schema_version: str
    files: Dict[str, Any]
    feature_columns: List[str]
    simulated: bool = True


class DatasetSampleResponse(BaseModel):
    split: str
    total_rows: int
    sample_size: int
    rows: List[Dict[str, Any]]
    simulated: bool = True


class DatasetStatsResponse(BaseModel):
    split: str
    total_rows: int
    class_distribution: Dict[str, int]
    feature_statistics: Dict[str, Any]
    simulated: bool = True


class DatasetGenerateRequest(BaseModel):
    seed: int = 42
    imbalanced: bool = False


class DatasetGenerateResponse(BaseModel):
    status: str
    message: str
    simulated: bool = True


# --- Models ---

class ModelManifestItem(BaseModel):
    name: str
    classifier_type: str
    schema_version: str
    data_source: str = "synthetic"
    active: bool = False
    trained_at: Optional[str] = None
    metrics_summary: Optional[Dict[str, Any]] = None


class ModelListResponse(BaseModel):
    models: List[Dict[str, Any]]
    active_model: str
    schema_version: str
    data_source: str = "synthetic"
    simulated: bool = True


class ModelTrainingRequest(BaseModel):
    classifier_type: str = "random_forest"  # random_forest | xgboost
    model_name: Optional[str] = None
    hyperparameters: Optional[Dict[str, Any]] = None
    dataset_split: Optional[str] = "train"


class ModelTrainingResponse(BaseModel):
    job_id: str
    model_name: str
    status: str
    message: str
    simulated: bool = True


class ModelTrainingStatusResponse(BaseModel):
    job_id: str
    model_name: str
    status: str
    progress: float
    metrics: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    simulated: bool = True


class ModelEvaluationResponse(BaseModel):
    model_name: str
    data_source: str = "synthetic"
    metrics: Dict[str, Any]
    simulated: bool = True


class ModelActivateRequest(BaseModel):
    model_name: str


class ModelActivateResponse(BaseModel):
    success: bool
    active_model: str
    message: str
    simulated: bool = True


class ModelPredictRequest(BaseModel):
    features: Dict[str, Any]


class ModelPredictResponse(BaseModel):
    prediction: str
    probability_ransomware: float
    class_probabilities: Dict[str, float]
    explanation: Dict[str, Any]
    model_name: str
    data_source: str = "synthetic"
    simulated: bool = True


# --- Settings & Configuration ---

class SettingsResponse(BaseModel):
    theta0: float = 0.5
    window: float = 2.0
    ewma_alpha: float = 0.4
    watch_threshold: float = 0.3
    suspect_threshold: float = 0.6
    critical_threshold: float = 0.85
    critical_confirm_windows: int = 2
    policy: str = "immediate"  # immediate | manual | none
    auto_resolve_timeout: float = 10.0
    allowlist: List[str] = Field(default_factory=list)
    panic_storm_threshold: int = 5
    mode: str = "simulated"
    simulated: bool = True


class SettingsUpdateRequest(BaseModel):
    theta0: Optional[float] = None
    window: Optional[float] = None
    ewma_alpha: Optional[float] = None
    watch_threshold: Optional[float] = None
    suspect_threshold: Optional[float] = None
    critical_threshold: Optional[float] = None
    critical_confirm_windows: Optional[int] = None
    policy: Optional[str] = None
    auto_resolve_timeout: Optional[float] = None
    allowlist: Optional[List[str]] = None
    panic_storm_threshold: Optional[int] = None
    mode: Optional[str] = None

