"""
CLI wrapper for AdaptShield model evaluation.
Refactored to delegate core evaluation and risk-replay logic to adaptshield.ml.evaluate.
"""
from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
from sklearn.model_selection import train_test_split

from adaptshield.ml.schema import TIER0_COLUMNS, FEATURE_COLUMNS
from adaptshield.ml.train import train_classifier
from adaptshield.ml.evaluate import evaluate_classifier


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data/raw/traces_test.csv")
    ap.add_argument("--train-data", default="data/raw/traces_train.csv")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    test_path = Path(args.data)
    train_path = Path(args.train_data)

    if test_path.exists() and train_path.exists():
        train_df = pd.read_csv(train_path)
        test_df = pd.read_csv(test_path)
    else:
        # Fall back to bootstrap if generated datasets not yet available
        bootstrap_files = sorted(glob.glob("results/raw/synthetic_traces_*.csv"))
        if not bootstrap_files:
            sys.exit("No trace data found to evaluate.")
        df = pd.concat([pd.read_csv(f) for f in bootstrap_files], ignore_index=True)
        train_df, test_df = train_test_split(df, test_size=0.3, stratify=df["label"], random_state=args.seed)

    print(f"Train rows: {len(train_df)}  Test rows: {len(test_df)}")

    # 1. XGBoost
    xgb = train_classifier("xgboost", train_df, seed=args.seed)
    metrics_xgb = evaluate_classifier(xgb, test_df, seed=args.seed)
    print("\n=== XGBoost ===")
    print(f"Accuracy:  {metrics_xgb['accuracy']:.4f}")
    print(f"F1 Score:  {metrics_xgb['f1']:.4f}")
    print(f"ROC-AUC:   {metrics_xgb['roc_auc']:.4f}")
    print("Confusion Matrix [[TN FP],[FN TP]]:", metrics_xgb['confusion_matrix'])

    # 2. Random Forest (Full)
    rf = train_classifier("random_forest", train_df, seed=args.seed)
    metrics_rf = evaluate_classifier(rf, test_df, seed=args.seed)
    print("\n=== Random Forest (Full) ===")
    print(f"Accuracy:  {metrics_rf['accuracy']:.4f}")
    print(f"F1 Score:  {metrics_rf['f1']:.4f}")
    print(f"ROC-AUC:   {metrics_rf['roc_auc']:.4f}")

    # 3. Random Forest (Tier-0 only ablation)
    rf_t0 = train_classifier("random_forest", train_df, columns=TIER0_COLUMNS, seed=args.seed)
    metrics_rf_t0 = evaluate_classifier(rf_t0, test_df, columns=TIER0_COLUMNS, seed=args.seed)
    print("\n=== Random Forest (Tier-0 only) ===")
    print(f"Accuracy:  {metrics_rf_t0['accuracy']:.4f}")
    print(f"F1 Score:  {metrics_rf_t0['f1']:.4f}")
    print(f"ROC-AUC:   {metrics_rf_t0['roc_auc']:.4f}")

    # 4. Rule-Based
    rb = train_classifier("rule_based", train_df, seed=args.seed)
    metrics_rb = evaluate_classifier(rb, test_df, seed=args.seed)
    print("\n=== Rule Based ===")
    print(f"Accuracy:  {metrics_rb['accuracy']:.4f}")
    print(f"F1 Score:  {metrics_rb['f1']:.4f}")
    print(f"ROC-AUC:   {metrics_rb['roc_auc']:.4f}")

    print("\n=== Risk-Scorer Replay (XGBoost) ===")
    for lbl, res in metrics_xgb["risk_scorer_replay"].items():
        print(f"{lbl:11s} Containment rate: {res['containment_rate']:.2%}  Mean windows: {res['mean_windows_to_detect']}")


if __name__ == "__main__":
    main()
