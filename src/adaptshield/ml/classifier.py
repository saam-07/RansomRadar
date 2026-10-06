"""
One interface, three interchangeable classifiers, so experiment_runner.py
can swap configurations without touching pipeline code:
  - RuleBasedClassifier   -> baseline 1 in the roadmap (Sec 6)
  - SklearnClassifier(RF) -> "ML-no-escalation" baseline uses this on Tier-0
                              features only; AdaptShield uses it on full features
  - XGBClassifierWrapper  -> the strongest baseline / AdaptShield's primary model
"""
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from adaptshield.feature_aggregator import FEATURE_COLUMNS

LABELS = ["benign", "backup", "oltp", "ransomware"]
POSITIVE_LABEL = "ransomware"


class RuleBasedClassifier:
    """Reproduces the 'activity volume alone' detector your Review-1 report
    argues (correctly) is insufficient. Exists so that insufficiency can be
    demonstrated experimentally, not just asserted."""

    def __init__(self, mod_rate_threshold: float = 80.0, rename_rate_threshold: float = 30.0):
        self.mod_rate_threshold = mod_rate_threshold
        self.rename_rate_threshold = rename_rate_threshold

    def fit(self, X: pd.DataFrame, y: pd.Series):
        return self  # nothing to fit; thresholds are fixed a priori

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        score = (
            (X["mod_rate"] >= self.mod_rate_threshold).astype(float) * 0.5
            + (X["rename_rate"] >= self.rename_rate_threshold).astype(float) * 0.5
        )
        return np.stack([1 - score, score], axis=1)

    def save(self, path: str):
        joblib.dump({
            "mod_rate_threshold": self.mod_rate_threshold,
            "rename_rate_threshold": self.rename_rate_threshold,
        }, path)

    def load(self, path: str):
        data = joblib.load(path)
        if isinstance(data, dict):
            self.mod_rate_threshold = data.get("mod_rate_threshold", self.mod_rate_threshold)
            self.rename_rate_threshold = data.get("rename_rate_threshold", self.rename_rate_threshold)
        return self


class SklearnClassifier:
    def __init__(self, columns: list[str] | None = None, **rf_kwargs):
        self.columns = columns or FEATURE_COLUMNS
        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=12, class_weight="balanced",
            random_state=42, **rf_kwargs,
        )

    def fit(self, X: pd.DataFrame, y: pd.Series):
        Xc = X[self.columns].fillna(-1.0)
        self.model.fit(Xc, y)
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        Xc = X[self.columns].fillna(-1.0)
        return self.model.predict_proba(Xc)

    def save(self, path: str):
        joblib.dump({"model": self.model, "columns": self.columns}, path)

    def load(self, path: str):
        data = joblib.load(path)
        if isinstance(data, dict):
            self.model = data["model"]
            self.columns = data.get("columns", self.columns)
        else:
            self.model = data
        return self


class XGBClassifierWrapper:
    def __init__(self, columns: list[str] | None = None, **xgb_kwargs):
        self.columns = columns or FEATURE_COLUMNS
        self.model = XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.05,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric="logloss", random_state=42, **xgb_kwargs,
        )

    def fit(self, X: pd.DataFrame, y: pd.Series):
        Xc = X[self.columns]  # XGBoost natively handles NaN as "missing"
        y_bin = (y == POSITIVE_LABEL).astype(int)
        self.model.fit(Xc, y_bin)
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        Xc = X[self.columns]
        return self.model.predict_proba(Xc)

    def save(self, path: str):
        joblib.dump({"model": self.model, "columns": self.columns}, path)

    def load(self, path: str):
        data = joblib.load(path)
        if isinstance(data, dict):
            self.model = data["model"]
            self.columns = data.get("columns", self.columns)
        else:
            self.model = data
        return self


def build_classifier(name: str, columns: list[str] | None = None):
    if name == "rule_based":
        return RuleBasedClassifier()
    if name == "random_forest":
        return SklearnClassifier(columns=columns)
    if name == "xgboost":
        return XGBClassifierWrapper(columns=columns)
    raise ValueError(f"Unknown classifier name: {name}")
