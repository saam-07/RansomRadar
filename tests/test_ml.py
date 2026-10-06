import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from adaptshield.feature_aggregator import FEATURE_COLUMNS
from adaptshield.ml.schema import (
    SCHEMA_VERSION,
    TIER0_COLUMNS,
    validate_features,
)
from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.train import train_classifier
from adaptshield.ml.evaluate import evaluate_classifier

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
REGISTRY_DIR = Path(__file__).resolve().parent.parent / "models" / "registry"


@pytest.fixture(scope="module")
def train_df():
    path = DATA_DIR / "traces_train.csv"
    assert path.exists(), "traces_train.csv missing"
    return pd.read_csv(path)


@pytest.fixture(scope="module")
def test_df():
    path = DATA_DIR / "traces_test.csv"
    assert path.exists(), "traces_test.csv missing"
    return pd.read_csv(path)


@pytest.fixture(scope="module")
def hard_test_df():
    path = DATA_DIR / "traces_hard_test.csv"
    assert path.exists(), "traces_hard_test.csv missing"
    return pd.read_csv(path)


def test_schema_validation_drops_metadata_and_retains_features(test_df):
    """Schema validation must strip pid, label, run_id, scenario, timestamp and keep FEATURE_COLUMNS."""
    assert "pid" in test_df.columns
    assert "label" in test_df.columns
    assert "run_id" in test_df.columns

    X_clean = validate_features(test_df)
    assert list(X_clean.columns) == FEATURE_COLUMNS
    assert "pid" not in X_clean.columns
    assert "label" not in X_clean.columns


def test_schema_validation_catches_missing_columns(test_df):
    """Schema validation must raise ValueError if required feature columns are missing."""
    incomplete_df = test_df.drop(columns=["mod_rate", "concentration_gini"])
    with pytest.raises(ValueError, match="Missing required column"):
        validate_features(incomplete_df)


def test_registry_rejects_mismatched_columns(train_df, tmp_path):
    """Registry must reject loading a model if expected columns do not match the manifest."""
    registry = ModelRegistry(registry_dir=tmp_path)
    clf = train_classifier("random_forest", train_df, columns=TIER0_COLUMNS, seed=42)
    registry.register_model("t0_model", clf, feature_columns=TIER0_COLUMNS)

    # Attempting to load expecting all 11 FEATURE_COLUMNS should raise ValueError
    with pytest.raises(ValueError, match="column mismatch"):
        registry.load_model("t0_model", expected_columns=FEATURE_COLUMNS)


def test_registry_loads_compatible_model(train_df, tmp_path):
    """Registry loads compatible model and verifies manifest."""
    registry = ModelRegistry(registry_dir=tmp_path)
    clf = train_classifier("rule_based", train_df, columns=FEATURE_COLUMNS)
    registry.register_model("rb_model", clf, feature_columns=FEATURE_COLUMNS, active=True)

    loaded_clf, manifest = registry.load_model("rb_model", expected_columns=FEATURE_COLUMNS)
    assert manifest["name"] == "rb_model"
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["active"] is True
    assert loaded_clf is not None


def test_training_is_reproducible_with_seed(train_df, test_df):
    """Training the same model with the same seed must produce identical predictions."""
    clf1 = train_classifier("xgboost", train_df, seed=42)
    clf2 = train_classifier("xgboost", train_df, seed=42)

    X_test = validate_features(test_df)
    proba1 = clf1.predict_proba(X_test)
    proba2 = clf2.predict_proba(X_test)

    np.testing.assert_allclose(proba1, proba2, atol=1e-5)


def test_hard_test_set_scores_lower_and_tier0_ablation():
    """Validates that metrics are realistic: hard test scores lower and ablation scores lower."""
    metrics_file = REGISTRY_DIR / "all_models_metrics.json"
    assert metrics_file.exists(), "all_models_metrics.json missing in registry"

    with open(metrics_file, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    models_dict = {m["name"]: m for m in metrics}

    xgb = models_dict["xgboost"]
    rf = models_dict["random_forest"]
    rf_t0 = models_dict["rf_tier0_ablation"]

    # 1. Hard test set F1 should score lower than standard test F1
    assert xgb["hard_test_f1"] < xgb["test_f1"], "Expected XGBoost hard test F1 to be lower than test F1"
    assert rf["hard_test_f1"] < rf["test_f1"], "Expected RF hard test F1 to be lower than test F1"

    # 2. Tier-0 ablation scores lower than full XGBoost
    assert rf_t0["hard_test_f1"] < xgb["hard_test_f1"], (
        f"Expected Tier-0 ablation hard test F1 ({rf_t0['hard_test_f1']}) "
        f"to be lower than full XGBoost ({xgb['hard_test_f1']})"
    )
