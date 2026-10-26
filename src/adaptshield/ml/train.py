"""
AdaptShield Model Training Module
=================================
Provides importable functions for fitting rule-based heuristics, Random Forest,
and XGBoost classifiers on feature datasets.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from adaptshield.classifier import build_classifier
from adaptshield.feature_aggregator import FEATURE_COLUMNS
from adaptshield.ml.schema import validate_features


def train_classifier(
    classifier_name: str,
    train_df: pd.DataFrame,
    columns: list[str] | None = None,
    seed: int = 42,
    **model_kwargs: Any,
) -> Any:
    """
    Trains a classifier on the provided DataFrame.

    Parameters:
        classifier_name: 'rule_based', 'random_forest', or 'xgboost'.
        train_df: Labeled DataFrame containing training feature rows.
        columns: Specific feature columns to train on (defaults to FEATURE_COLUMNS).
        seed: Random state seed.
        model_kwargs: Additional parameters passed to classifier constructor.

    Returns:
        Trained classifier instance.
    """
    feature_cols = list(columns or FEATURE_COLUMNS)
    X = validate_features(train_df, expected_columns=feature_cols)
    y = train_df["label"]

    if classifier_name == "rule_based":
        clf = build_classifier("rule_based")
        clf.fit(X, y)
    elif classifier_name == "random_forest":
        clf = build_classifier("random_forest", columns=feature_cols)
        valid_params = set(clf.model.get_params().keys())
        kwargs = {k: v for k, v in model_kwargs.items() if k in valid_params}
        kwargs["random_state"] = seed
        clf.model.set_params(**kwargs)
        clf.fit(X, y)
    elif classifier_name == "xgboost":
        clf = build_classifier("xgboost", columns=feature_cols)
        valid_params = set(clf.model.get_params().keys())
        kwargs = {k: v for k, v in model_kwargs.items() if k in valid_params}
        kwargs["random_state"] = seed
        clf.model.set_params(**kwargs)
        clf.fit(X, y)
    else:
        raise ValueError(f"Unknown classifier: {classifier_name}")

    return clf
