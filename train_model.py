"""
CLI wrapper for AdaptShield model training.
Refactored to delegate core training logic to adaptshield.ml.train.
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

from adaptshield.ml.train import train_classifier
from adaptshield.ml.registry import ModelRegistry


def load_traces(include_synthetic: bool = True) -> pd.DataFrame:
    """Loads available training trace CSV files."""
    candidates = [
        "data/raw/traces_train.csv",
        "results/raw/traces_*.csv",
    ]
    if include_synthetic:
        candidates.append("results/raw/synthetic_traces_*.csv")

    files = []
    for pattern in candidates:
        files.extend(glob.glob(pattern))
    files = sorted(list(set(files)))

    if not files:
        sys.exit(
            "No trace files found under data/raw/traces_train.csv or results/raw/.\n"
            "Run 'make data' or 'python scripts/make_datasets.py' first."
        )

    frames = [pd.read_csv(f) for f in files]
    df = pd.concat(frames, ignore_index=True)
    print(f"Loaded {len(files)} trace file(s), total rows: {len(df)}")
    return df


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--classifier", default="xgboost", choices=["random_forest", "xgboost", "rule_based"])
    ap.add_argument("--data", default=None, help="Path to specific training trace CSV")
    ap.add_argument("--include-synthetic", action="store_true", default=True)
    ap.add_argument("--out", default="results/processed/xgb_model.joblib")
    ap.add_argument("--register", action="store_true", help="Also register model in models/registry/")
    args = ap.parse_args()

    if args.data:
        df = pd.read_csv(args.data)
    else:
        df = load_traces(args.include_synthetic)

    clf = train_classifier(args.classifier, df)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    clf.save(str(out_path))
    print(f"Saved trained {args.classifier} model to {out_path}")

    if args.register:
        registry = ModelRegistry()
        registry.register_model(name=args.classifier, classifier=clf, active=True)
        print(f"Registered model '{args.classifier}' in models/registry/")


if __name__ == "__main__":
    main()
