"""
Datasets inspection, sampling, statistics, and generator triggering endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd
from fastapi import APIRouter, HTTPException, Query

from adaptshield.ml.schema import FEATURE_COLUMNS, SCHEMA_VERSION
from backend.app.schemas import (
    DatasetListResponse,
    DatasetSampleResponse,
    DatasetStatsResponse,
    DatasetGenerateRequest,
    DatasetGenerateResponse,
)

router = APIRouter()
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DATA_DIR = REPO_ROOT / "data"
MANIFEST_PATH = DATA_DIR / "manifest.json"


@router.get("/datasets", response_model=DatasetListResponse)
def get_datasets_overview():
    """Returns dataset manifests, class counts, row counts, and schema version."""
    if not MANIFEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Dataset manifest not found")

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    return DatasetListResponse(
        generator_version=manifest.get("generator_version", "1.0.0"),
        schema_version=manifest.get("schema_version", SCHEMA_VERSION),
        files=manifest.get("splits", {}),
        feature_columns=FEATURE_COLUMNS,
        simulated=True,
    )


@router.get("/datasets/{split}/sample", response_model=DatasetSampleResponse)
def get_dataset_sample(
    split: str,
    label: Optional[str] = None,
    limit: int = Query(default=20, ge=1, le=100),
):
    """Returns a sample of rows from a dataset split (train, val, test, hard_test)."""
    csv_file = DATA_DIR / "raw" / f"traces_{split}.csv"
    if not csv_file.exists():
        raise HTTPException(status_code=404, detail=f"Split traces_{split}.csv not found")

    df = pd.read_csv(csv_file)
    if label:
        df = df[df["label"] == label]

    sample_df = df.head(limit)
    # Replace NaN with None for clean JSON serialization
    records = sample_df.where(pd.notnull(sample_df), None).to_dict(orient="records")

    return DatasetSampleResponse(
        split=split,
        total_rows=len(df),
        sample_size=len(records),
        rows=records,
        simulated=True,
    )


@router.get("/datasets/{split}/stats", response_model=DatasetStatsResponse)
def get_dataset_stats(split: str):
    """Computes distribution statistics per feature per class for the split."""
    csv_file = DATA_DIR / "raw" / f"traces_{split}.csv"
    if not csv_file.exists():
        raise HTTPException(status_code=404, detail=f"Split traces_{split}.csv not found")

    df = pd.read_csv(csv_file)
    class_dist = df["label"].value_counts().to_dict()

    feature_stats: Dict[str, Any] = {}
    for col in FEATURE_COLUMNS:
        if col in df.columns:
            stats_by_class: Dict[str, Any] = {}
            for cls_name, grp in df.groupby("label"):
                s = grp[col].dropna()
                stats_by_class[str(cls_name)] = {
                    "mean": round(float(s.mean()), 4) if len(s) > 0 else 0.0,
                    "std": round(float(s.std()), 4) if len(s) > 0 else 0.0,
                    "min": round(float(s.min()), 4) if len(s) > 0 else 0.0,
                    "max": round(float(s.max()), 4) if len(s) > 0 else 0.0,
                    "p50": round(float(s.median()), 4) if len(s) > 0 else 0.0,
                }
            feature_stats[col] = stats_by_class

    return DatasetStatsResponse(
        split=split,
        total_rows=len(df),
        class_distribution=class_dist,
        feature_statistics=feature_stats,
        simulated=True,
    )


@router.post("/datasets/generate", response_model=DatasetGenerateResponse)
def trigger_dataset_generation(payload: DatasetGenerateRequest):
    """Triggers generation of new benchmark datasets."""
    from scripts.make_datasets import generate_datasets
    try:
        manifest = generate_datasets(seed=payload.seed, imbalanced_ratio=0.999 if payload.imbalanced else None)
        return DatasetGenerateResponse(
            status="completed",
            message=f"Datasets regenerated successfully with seed={payload.seed}",
            simulated=True,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dataset generation failed: {e}")
