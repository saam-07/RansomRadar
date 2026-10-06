#!/usr/bin/env python3
"""
AdaptShield Multi-Model Training & Registry Pipeline
====================================================
Trains and registers all benchmark and ablation models on data/raw/traces_train.csv,
evaluates on traces_test.csv and traces_hard_test.csv, computes comprehensive metrics,
and saves versioned manifests in models/registry/.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from adaptshield.feature_aggregator import FEATURE_COLUMNS
from adaptshield.ml.schema import TIER0_COLUMNS
from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.train import train_classifier
from adaptshield.ml.evaluate import evaluate_classifier


def train_and_register_all(
    data_dir: Path | str = "data/raw",
    registry_dir: Path | str = "models/registry",
    seed: int = 42,
) -> None:
    data_path = Path(data_dir)
    train_path = data_path / "traces_train.csv"
    val_path = data_path / "traces_val.csv"
    test_path = data_path / "traces_test.csv"
    hard_test_path = data_path / "traces_hard_test.csv"

    for p in [train_path, test_path, hard_test_path]:
        if not p.exists():
            raise FileNotFoundError(
                f"Missing dataset file: {p}. Run 'make data' or 'python scripts/make_datasets.py' first."
            )

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path) if val_path.exists() else None
    test_df = pd.read_csv(test_path)
    hard_test_df = pd.read_csv(hard_test_path)

    print(f"Loaded datasets: Train={len(train_df)}, Val={len(val_df) if val_df is not None else 0}, "
          f"Test={len(test_df)}, HardTest={len(hard_test_df)}")

    registry = ModelRegistry(registry_dir=registry_dir)

    models_to_train = [
        # (name, classifier_type, columns, is_active)
        ("rule_based", "rule_based", FEATURE_COLUMNS, False),
        ("rf_tier0_ablation", "random_forest", TIER0_COLUMNS, False),
        ("random_forest", "random_forest", FEATURE_COLUMNS, False),
        ("xgboost", "xgboost", FEATURE_COLUMNS, True),  # Active default detector
    ]

    summary_records = []

    for name, ctype, cols, is_active in models_to_train:
        print(f"\n---> Training and evaluating: {name} (features={len(cols)})...")
        clf = train_classifier(ctype, train_df, columns=cols, seed=seed)

        metrics = evaluate_classifier(
            clf=clf,
            test_df=test_df,
            hard_test_df=hard_test_df,
            columns=cols,
            imbalanced_ratio=0.999,
            seed=seed,
        )

        model_dir = registry.register_model(
            name=name,
            classifier=clf,
            feature_columns=cols,
            data_source="synthetic",
            metrics=metrics,
            seed=seed,
            active=is_active,
        )

        test_f1 = metrics["f1"]
        hard_f1 = metrics.get("hard_test", {}).get("f1", 0.0)
        print(f"     Registered in: {model_dir}")
        print(f"     Test F1: {test_f1:.4f} | ROC-AUC: {metrics['roc_auc']:.4f} | Hard-Test F1: {hard_f1:.4f}")

        summary_records.append({
            "name": name,
            "classifier_type": ctype,
            "columns_count": len(cols),
            "test_accuracy": metrics["accuracy"],
            "test_f1": metrics["f1"],
            "test_roc_auc": metrics["roc_auc"],
            "hard_test_accuracy": metrics.get("hard_test", {}).get("accuracy"),
            "hard_test_f1": hard_f1,
            "hard_test_roc_auc": metrics.get("hard_test", {}).get("roc_auc"),
            "false_positives_per_hour": metrics["false_positives_per_hour"],
        })

    # Register legacy synthetic bootstrap joblib models if present
    legacy_xgb_src = Path("results/processed/xgb_model.joblib")
    legacy_rf_src = Path("results/processed/rf_model.joblib")

    if legacy_xgb_src.exists():
        print("\n---> Registering legacy synthetic bootstrap XGBoost model...")
        registry.register_existing_joblib(
            name="legacy_synthetic_xgb",
            joblib_path=legacy_xgb_src,
            classifier_type="xgboost",
            feature_columns=FEATURE_COLUMNS,
            data_source="synthetic_bootstrap_legacy",
            metrics={"note": "Trained on legacy synthetic_traces_bootstrap.csv, for backwards-compatibility testing only."},
            active=False,
        )

    if legacy_rf_src.exists():
        print("---> Registering legacy synthetic bootstrap Random Forest model...")
        registry.register_existing_joblib(
            name="legacy_synthetic_rf",
            joblib_path=legacy_rf_src,
            classifier_type="random_forest",
            feature_columns=FEATURE_COLUMNS,
            data_source="synthetic_bootstrap_legacy",
            metrics={"note": "Trained on legacy synthetic_traces_bootstrap.csv, for backwards-compatibility testing only."},
            active=False,
        )

    # Save consolidated metrics summary JSON
    summary_path = Path(registry_dir) / "all_models_metrics.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_records, f, indent=2)

    print(f"\nAll models successfully trained and registered. Summary saved to {summary_path}")


def main():
    parser = argparse.ArgumentParser(description="Train and register all AdaptShield classifiers.")
    parser.add_argument("--data-dir", default="data/raw", help="Path to raw traces CSVs")
    parser.add_argument("--registry-dir", default="models/registry", help="Path to model registry")
    parser.add_argument("--seed", type=int, default=42, help="Random state seed")
    args = parser.parse_args()

    train_and_register_all(
        data_dir=args.data_dir,
        registry_dir=args.registry_dir,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
