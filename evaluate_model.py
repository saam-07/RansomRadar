"""
Evaluates the classifiers on a held-out split and replays the full ML path
(feature row -> classifier -> EWMA RiskScorer -> CRITICAL decision) exactly as
daemon.py does, but offline (no fanotify / eBPF / root needed).

Usage:
    PYTHONPATH=. python evaluate_model.py                       # synthetic bootstrap
    PYTHONPATH=. python evaluate_model.py --glob "results/raw/traces_*.csv"   # real traces

NOTE: numbers from synthetic data only prove the plumbing works.
"""
import argparse
import glob

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

from adaptshield.classifier import build_classifier, POSITIVE_LABEL
from adaptshield.feature_aggregator import FEATURE_COLUMNS
from adaptshield.risk_scorer import RiskScorer, RiskLevel

TIER0 = ["mod_rate", "rename_rate", "create_del_rate", "event_count", "concentration_gini"]


def evaluate(name, df_train, df_test, columns=None):
    clf = build_classifier(name, columns=columns)
    clf.fit(df_train, df_train["label"])
    proba = clf.predict_proba(df_test)
    p = proba[:, 1] if proba.shape[1] == 2 else proba[:, -1]
    y = (df_test["label"] == POSITIVE_LABEL).astype(int).values
    pred = (p >= 0.5).astype(int)
    print(f"\n=== {name} {'(Tier-0 only)' if columns == TIER0 else ''} ===")
    print(classification_report(y, pred, target_names=["not_ransomware", "ransomware"], digits=3))
    print("Confusion matrix [[TN FP],[FN TP]]:\n", confusion_matrix(y, pred))
    if len(set(y)) == 2:
        print(f"ROC-AUC: {roc_auc_score(y, p):.4f}")
    return clf


def replay_through_risk_scorer(clf, df_test, windows=10, seed=0):
    """Simulates one PID per class emitting `windows` consecutive windows and
    reports whether the EWMA scorer reaches CRITICAL (what triggers containment)."""
    rng = np.random.default_rng(seed)
    print("\n=== Risk-scorer replay (fraction of simulated PIDs reaching CRITICAL) ===")
    for label in ["benign", "backup", "oltp", "ransomware"]:
        pool = df_test[df_test["label"] == label]
        n_pids, critical, first_win = 100, 0, []
        for _ in range(n_pids):
            scorer = RiskScorer()
            rows = pool.sample(windows, replace=True, random_state=int(rng.integers(1e9)))
            proba = clf.predict_proba(rows)
            p = proba[:, 1] if proba.shape[1] == 2 else proba[:, -1]
            for i, pi in enumerate(p, 1):
                if scorer.update(1, float(pi)) == RiskLevel.CRITICAL:
                    critical += 1
                    first_win.append(i)
                    break
        mean_w = f"{np.mean(first_win):.1f}" if first_win else "-"
        print(f"{label:11s} CRITICAL: {critical:3d}/{n_pids}   mean windows to detect: {mean_w}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default="results/raw/synthetic_traces_*.csv")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    files = sorted(glob.glob(args.glob))
    if not files:
        raise SystemExit(f"No files match {args.glob}")
    df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    tr, te = train_test_split(df, test_size=0.3, stratify=df["label"], random_state=args.seed)
    print(f"Train rows: {len(tr)}  Test rows: {len(te)}")

    xgb = evaluate("xgboost", tr, te)
    evaluate("random_forest", tr, te)
    evaluate("random_forest", tr, te, columns=TIER0)   # baseline 3: Tier-0 only
    evaluate("rule_based", tr, te)                      # baseline 1

    replay_through_risk_scorer(xgb, te)

    imp = sorted(zip(FEATURE_COLUMNS, xgb.model.feature_importances_), key=lambda t: -t[1])
    print("\nXGBoost feature importance:")
    for f, v in imp:
        print(f"  {f:20s} {v:.3f}")


if __name__ == "__main__":
    main()
