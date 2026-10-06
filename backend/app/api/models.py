"""
Machine learning model registry, evaluation, training, activation, and prediction endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.schema import FEATURE_COLUMNS, SCHEMA_VERSION, validate_features
from adaptshield.ml.evaluate import extract_ransomware_prob
from backend.app.core.explain import explain_alert
from backend.app.db.session import get_db
from backend.app.db.models import TrainingJobRecord
from backend.app.schemas import (
    ModelListResponse,
    ModelTrainingRequest,
    ModelTrainingResponse,
    ModelTrainingStatusResponse,
    ModelEvaluationResponse,
    ModelActivateRequest,
    ModelActivateResponse,
    ModelPredictRequest,
    ModelPredictResponse,
)
from backend.app.services.system_state import SystemStateManager

router = APIRouter()
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


@router.get("/models", response_model=ModelListResponse)
def list_registered_models():
    """Lists all models in registry with manifests, status, and metrics summary."""
    registry = ModelRegistry()
    models = registry.list_models()
    active_model = "unknown"
    for m in models:
        if m.get("active"):
            active_model = m.get("name", "unknown")
            break

    return ModelListResponse(
        models=models,
        active_model=active_model,
        schema_version=SCHEMA_VERSION,
        data_source="synthetic",
        simulated=True,
    )


@router.get("/models/{model_name}/evaluation", response_model=ModelEvaluationResponse)
def get_model_evaluation(model_name: str):
    """Retrieves full evaluation report for a registered model."""
    registry = ModelRegistry()
    manifest_path = registry.registry_dir / model_name / "manifest.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=404, detail=f"Model '{model_name}' not found in registry")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    metrics = manifest.get("metrics", {})
    return ModelEvaluationResponse(
        model_name=model_name,
        data_source=manifest.get("data_source", "synthetic"),
        metrics=metrics,
        simulated=True,
    )


@router.post("/models/activate", response_model=ModelActivateResponse)
def activate_model(payload: ModelActivateRequest):
    """
    Activates a model from the registry.
    Performs schema and column compatibility checks, rejecting incompatible models.
    """
    state = SystemStateManager.get_instance()
    try:
        # Compatibility check against system FEATURE_COLUMNS
        state.registry.load_model(payload.model_name, expected_columns=FEATURE_COLUMNS)
        # If valid, activate
        state.registry.set_active_model(payload.model_name)
        state.set_detector(payload.model_name)
        return ModelActivateResponse(
            success=True,
            active_model=payload.model_name,
            message=f"Model '{payload.model_name}' validated and activated successfully",
            simulated=True,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Model compatibility check failed: {e}")
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to activate model: {e}")


@router.post("/models/train", response_model=ModelTrainingResponse)
def trigger_training_job(payload: ModelTrainingRequest):
    """Triggers a model training job as a background process."""
    state = SystemStateManager.get_instance()
    try:
        job_id = state.start_training_job(
            classifier_type=payload.classifier_type,
            model_name=payload.model_name,
            hyperparameters=payload.hyperparameters,
        )
        name = payload.model_name or f"{payload.classifier_type}_model"
        return ModelTrainingResponse(
            job_id=job_id,
            model_name=name,
            status="queued",
            message=f"Training job queued for {payload.classifier_type}",
            simulated=True,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start training job: {e}")


@router.get("/models/training/{job_id}", response_model=ModelTrainingStatusResponse)
def get_training_job_status(job_id: str, db: Session = Depends(get_db)):
    """Checks the progress and completion status of a model training job."""
    job = db.query(TrainingJobRecord).filter(TrainingJobRecord.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Training job not found")

    metrics = None
    if job.metrics_json:
        try:
            metrics = json.loads(job.metrics_json)
        except Exception:
            metrics = None

    return ModelTrainingStatusResponse(
        job_id=job.id,
        model_name=job.model_name,
        status=job.status,
        progress=job.progress,
        metrics=metrics,
        error=job.error_message,
        simulated=True,
    )


@router.post("/models/predict", response_model=ModelPredictResponse)
def predict_features(payload: ModelPredictRequest):
    """
    Evaluates an input feature vector with the active detector.
    Validates input schema and returns class probabilities with explanation.
    """
    state = SystemStateManager.get_instance()
    try:
        # Validate features according to schema
        X_clean = validate_features(payload.features, expected_columns=state.pipeline.feature_columns)
        prob_rw = float(extract_ransomware_prob(state.pipeline.classifier, X_clean)[0])
        explanation = explain_alert(
            classifier=state.pipeline.classifier,
            feature_row=payload.features,
            classifier_name=state.pipeline.model_name,
        )

        prediction_label = "ransomware" if prob_rw >= 0.5 else "benign"
        return ModelPredictResponse(
            prediction=prediction_label,
            probability_ransomware=round(prob_rw, 4),
            class_probabilities={
                "benign": round(1.0 - prob_rw, 4),
                "ransomware": round(prob_rw, 4),
            },
            explanation=explanation,
            model_name=state.pipeline.model_name,
            data_source=state.pipeline.active_manifest.get("data_source", "synthetic"),
            simulated=True,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Feature validation error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {e}")
