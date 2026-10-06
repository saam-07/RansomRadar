"""
AdaptShield Model Evaluation Module
===================================
Computes comprehensive validation and test metrics for registered classifiers:
- Precision, Recall, F1, ROC-AUC, PR-AUC, Confusion Matrix
- Subsampled ROC and PR curve coordinate points (for frontend charts)
- Per-class classification metrics
- Per-scenario family breakdown (detection rate & mean probability)
- Feature importance ranking
- Estimated False Positives per hour at imbalanced ratios
- EWMA Risk-Scorer replay (mean windows to detect & containment triggers)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from adaptshield.classifier import POSITIVE_LABEL
from adaptshield.feature_aggregator import FEATURE_COLUMNS
from adaptshield.ml.schema import validate_features
from adaptshield.risk_scorer import RiskLevel, RiskScorer


def extract_ransomware_prob(clf: Any, X: pd.DataFrame) -> np.ndarray:
    """Extracts the continuous probability of the positive 'ransomware' class."""
    proba = clf.predict_proba(X)
    if proba.ndim == 1:
        return proba

    if proba.shape[1] == 2:
        return proba[:, 1]

    # Multi-class scenario: check if classifier has classes_ attribute
    if hasattr(clf, "model") and hasattr(clf.model, "classes_"):
        classes = list(clf.model.classes_)
        if POSITIVE_LABEL in classes:
            idx = classes.index(POSITIVE_LABEL)
            return proba[:, idx]

    # Fallback to last column
    return proba[:, -1]


def subsample_curve_points(
    x_vals: np.ndarray, y_vals: np.ndarray, max_points: int = 30
) -> List[Dict[str, float]]:
    """Subsamples ROC or PR curve arrays to a JSON-serializable list of points."""
    n = len(x_vals)
    if n <= max_points:
        indices = list(range(n))
    else:
        indices = np.linspace(0, n - 1, max_points, dtype=int).tolist()

    points = []
    for idx in indices:
        points.append({
            "x": round(float(x_vals[idx]), 4),
            "y": round(float(y_vals[idx]), 4),
        })
    return points


def replay_risk_scorer(
    clf: Any,
    df: pd.DataFrame,
    columns: List[str] | None = None,
    windows: int = 15,
    n_pids: int = 50,
    seed: int = 42,
) -> Dict[str, Dict[str, Any]]:
    """
    Replays feature rows through the exact EWMA RiskScorer used by the live daemon.
    Reports the fraction of simulated runs reaching CRITICAL and the mean windows to detect.
    """
    rng = np.random.default_rng(seed)
    feature_cols = list(columns or FEATURE_COLUMNS)
    results: Dict[str, Dict[str, Any]] = {}

    labels = ["benign", "backup", "oltp", "ransomware"]
    for label in labels:
        pool = df[df["label"] == label]
        if len(pool) == 0:
            continue

        critical_count = 0
        windows_to_detect: List[int] = []

        for _ in range(n_pids):
            scorer = RiskScorer(alpha=0.4, critical_confirm_windows=2)
            # Sample consecutive windows or random windows from this class
            rows = pool.sample(n=min(windows, len(pool)), replace=True, random_state=int(rng.integers(1e9)))
            X_clean = validate_features(rows, expected_columns=feature_cols)
            probs = extract_ransomware_prob(clf, X_clean)

            detected = False
            for w_idx, prob in enumerate(probs, start=1):
                level = scorer.update(1, float(prob))
                if level == RiskLevel.CRITICAL:
                    critical_count += 1
                    windows_to_detect.append(w_idx)
                    detected = True
                    break

        mean_w = float(np.mean(windows_to_detect)) if windows_to_detect else None
        results[label] = {
            "containment_rate": round(critical_count / n_pids, 4),
            "contained_count": critical_count,
            "total_simulated": n_pids,
            "mean_windows_to_detect": round(mean_w, 2) if mean_w is not None else None,
        }

    return results


def evaluate_classifier(
    clf: Any,
    test_df: pd.DataFrame,
    hard_test_df: pd.DataFrame | None = None,
    columns: List[str] | None = None,
    imbalanced_ratio: float = 0.999,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    Computes all standard metrics, breakdown charts, false-alarm estimates,
    and risk-scorer replays for a classifier.
    """
    feature_cols = list(columns or FEATURE_COLUMNS)
    X_test = validate_features(test_df, expected_columns=feature_cols)
    y_test_bin = (test_df["label"] == POSITIVE_LABEL).astype(int).values

    probs = extract_ransomware_prob(clf, X_test)
    preds_bin = (probs >= 0.5).astype(int)

    # Core binary metrics
    acc = float(accuracy_score(y_test_bin, preds_bin))
    prec = float(precision_score(y_test_bin, preds_bin, zero_division=0))
    rec = float(recall_score(y_test_bin, preds_bin, zero_division=0))
    f1 = float(f1_score(y_test_bin, preds_bin, zero_division=0))

    try:
        roc_auc = float(roc_auc_score(y_test_bin, probs))
    except Exception:
        roc_auc = 0.5

    try:
        pr_auc = float(average_precision_score(y_test_bin, probs))
    except Exception:
        pr_auc = 0.0

    cm = confusion_matrix(y_test_bin, preds_bin).tolist()

    # ROC & PR Curves
    try:
        fpr, tpr, _ = roc_curve(y_test_bin, probs)
        roc_points = subsample_curve_points(fpr, tpr)
    except Exception:
        roc_points = []

    try:
        prec_curve, rec_curve, _ = precision_recall_curve(y_test_bin, probs)
        pr_points = subsample_curve_points(rec_curve, prec_curve)
    except Exception:
        pr_points = []

    # Per-scenario breakdown
    scenario_metrics: Dict[str, Dict[str, Any]] = {}
    if "scenario" in test_df.columns:
        for sc in sorted(test_df["scenario"].unique()):
            mask = (test_df["scenario"] == sc).values
            sc_probs = probs[mask]
            sc_preds = preds_bin[mask]
            scenario_metrics[sc] = {
                "count": int(np.sum(mask)),
                "detection_rate": round(float(np.mean(sc_preds)), 4),
                "mean_probability": round(float(np.mean(sc_probs)), 4),
            }

    # Per-class metrics
    class_report: Dict[str, Any] = {}
    if "label" in test_df.columns:
        for lbl in ["benign", "backup", "oltp", "ransomware"]:
            mask = (test_df["label"] == lbl).values
            if np.sum(mask) > 0:
                class_report[lbl] = {
                    "count": int(np.sum(mask)),
                    "flagged_as_ransomware_rate": round(float(np.mean(preds_bin[mask])), 4),
                    "mean_probability": round(float(np.mean(probs[mask])), 4),
                }

    # Feature importances
    feature_importances: List[Dict[str, Any]] = []
    if hasattr(clf, "model") and hasattr(clf.model, "feature_importances_"):
        imps = clf.model.feature_importances_
        sorted_pairs = sorted(zip(feature_cols, imps), key=lambda x: -x[1])
        feature_importances = [
            {"feature": col, "importance": round(float(val), 4)} for col, val in sorted_pairs
        ]
    elif isinstance(getattr(clf, "model", None), dict) or hasattr(clf, "mod_rate_threshold"):
        # Rule based heuristic weights
        feature_importances = [
            {"feature": "mod_rate", "importance": 0.50},
            {"feature": "rename_rate", "importance": 0.50},
        ]

    # False-positives per hour estimation at imbalanced ratio (2-second windows = 1800 windows/hour)
    # FPR on benign = FP / (FP + TN)
    tn = cm[0][0]
    fp = cm[0][1]
    fpr_benign = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fp_per_hour = round(fpr_benign * 1800 * imbalanced_ratio, 2)

    # Risk-Scorer Replay
    risk_replay = replay_risk_scorer(clf, test_df, columns=feature_cols, seed=seed)

    metrics_payload: Dict[str, Any] = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": cm,
        "roc_curve": roc_points,
        "pr_curve": pr_points,
        "class_report": class_report,
        "scenario_breakdown": scenario_metrics,
        "feature_importances": feature_importances,
        "false_positives_per_hour": fp_per_hour,
        "risk_scorer_replay": risk_replay,
    }

    # Evaluate on held-out hard test set if provided
    if hard_test_df is not None:
        X_hard = validate_features(hard_test_df, expected_columns=feature_cols)
        y_hard_bin = (hard_test_df["label"] == POSITIVE_LABEL).astype(int).values
        hard_probs = extract_ransomware_prob(clf, X_hard)
        hard_preds = (hard_probs >= 0.5).astype(int)

        try:
            hard_auc = float(roc_auc_score(y_hard_bin, hard_probs))
        except Exception:
            hard_auc = 0.5

        metrics_payload["hard_test"] = {
            "accuracy": round(float(accuracy_score(y_hard_bin, hard_preds)), 4),
            "precision": round(float(precision_score(y_hard_bin, hard_preds, zero_division=0)), 4),
            "recall": round(float(recall_score(y_hard_bin, hard_preds, zero_division=0)), 4),
            "f1": round(float(f1_score(y_hard_bin, hard_preds, zero_division=0)), 4),
            "roc_auc": round(hard_auc, 4),
            "confusion_matrix": confusion_matrix(y_hard_bin, hard_preds).tolist(),
            "risk_scorer_replay": replay_risk_scorer(clf, hard_test_df, columns=feature_cols, seed=seed),
        }

    return metrics_payload
