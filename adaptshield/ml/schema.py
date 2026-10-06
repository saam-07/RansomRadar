"""
AdaptShield Feature Schema Module
=================================
Defines the canonical feature contract for AdaptShield machine learning models.
Validates input DataFrames/dictionaries prior to inference:
- Enforces expected column presence and order.
- Drops metadata columns (pid, label, run_id, scenario, timestamp, etc.).
- Casts to numeric dtypes.
- Handles Tier-1 NaN values (allowed when Tier-1 escalation has not occurred).
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence
import numpy as np
import pandas as pd

from adaptshield.feature_aggregator import FEATURE_COLUMNS

SCHEMA_VERSION = "1.0.0"

TIER0_COLUMNS: List[str] = [
    "mod_rate",
    "rename_rate",
    "create_del_rate",
    "event_count",
    "concentration_gini",
]

TIER1_COLUMNS: List[str] = [
    "t1_write_rate",
    "t1_mean_entropy",
    "t1_entropy_std",
    "t1_unlink_rate",
    "t1_rename_rate",
    "t1_mean_write_size",
]

# Non-feature metadata columns that must be stripped before inference
METADATA_COLUMNS: List[str] = [
    "pid",
    "run_id",
    "scenario",
    "label",
    "window_idx",
    "timestamp",
    "source",
    "id",
]


def get_feature_columns() -> List[str]:
    """Returns a copy of the canonical 11 feature column names."""
    return list(FEATURE_COLUMNS)


def validate_features(
    data: pd.DataFrame | Dict[str, Any] | Sequence[Dict[str, Any]],
    expected_columns: Sequence[str] | None = None,
    allow_nan_tier1: bool = True,
) -> pd.DataFrame:
    """
    Validates and cleans input data against the feature schema contract.

    Parameters:
        data: DataFrame or dict(s) containing feature rows.
        expected_columns: List of columns required by the model (defaults to FEATURE_COLUMNS).
        allow_nan_tier1: If True, keeps NaN in Tier-1 columns for unescalated processes.

    Returns:
        pd.DataFrame containing strictly the expected feature columns in correct order.

    Raises:
        ValueError: If required feature columns are missing from the input data.
    """
    if expected_columns is None:
        target_cols = FEATURE_COLUMNS
    else:
        target_cols = list(expected_columns)

    if isinstance(data, dict):
        df = pd.DataFrame([data])
    elif isinstance(data, list):
        df = pd.DataFrame(data)
    elif isinstance(data, pd.DataFrame):
        df = data.copy()
    else:
        raise TypeError(f"Expected DataFrame or dict/list of dicts, got {type(data)}")

    # Drop non-feature metadata columns if present
    cols_to_drop = [c for c in METADATA_COLUMNS if c in df.columns and c not in target_cols]
    if cols_to_drop:
        df = df.drop(columns=cols_to_drop)

    # Check for missing required feature columns
    missing = [c for c in target_cols if c not in df.columns]
    if missing:
        raise ValueError(
            f"Input features violate schema version {SCHEMA_VERSION}. "
            f"Missing required column(s): {missing}"
        )

    # Select only the target columns in canonical order
    df = df[target_cols]

    # Convert numeric types
    for col in target_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Tier-0 features must not be NaN
    tier0_present = [c for c in TIER0_COLUMNS if c in target_cols]
    if tier0_present and df[tier0_present].isna().any().any():
        df[tier0_present] = df[tier0_present].fillna(0.0)

    # Tier-1 features handling
    if not allow_nan_tier1:
        tier1_present = [c for c in TIER1_COLUMNS if c in target_cols]
        if tier1_present and df[tier1_present].isna().any().any():
            df[tier1_present] = df[tier1_present].fillna(-1.0)

    return df
