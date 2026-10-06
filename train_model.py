"""
Trains a classifier from labeled trace CSVs produced by
dataset/generate_labeled_traces.py and saves it for the daemon to load.

Usage:
    python3 train_model.py                          # real traces only (default)
    python3 train_model.py --include-synthetic       # also mixes in the
                                                        # synthetic bootstrap
                                                        # dataset (see
                                                        # dataset/make_synthetic_bootstrap.py)
                                                        # -- ONLY for exercising
                                                        # the pipeline before you
                                                        # have real kernel traces.
                                                        # Never use a
                                                        # synthetic-trained model
                                                        # for your reported results.
    python3 train_model.py --classifier random_forest --out results/processed/rf_model.joblib
"""
import argparse
import glob
import sys

import pandas as pd

from adaptshield.classifier import build_classifier


def load_traces(include_synthetic: bool) -> pd.DataFrame:
    real_files = sorted(glob.glob("results/raw/traces_*.csv"))
    synthetic_files = sorted(glob.glob("results/raw/synthetic_traces_*.csv")) if include_synthetic else []

    if not real_files and not synthetic_files:
        sys.exit(
            "No trace files found under results/raw/traces_*.csv.\n"
            "Run dataset/generate_labeled_traces.py first (see README Phase 5), "
            "or re-run this script with --include-synthetic after running "
            "dataset/make_synthetic_bootstrap.py to at least test the pipeline."
        )

    frames = []
    for f in real_files:
        df = pd.read_csv(f)
        df["source"] = "real"
        frames.append(df)
    for f in synthetic_files:
        df = pd.read_csv(f)
        df["source"] = "synthetic"
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    print(f"Loaded {len(real_files)} real trace file(s), {len(synthetic_files)} synthetic file(s).")
    print("Row count by label:")
    print(combined["label"].value_counts())
    print("Row count by source:")
    print(combined["source"].value_counts())

    if synthetic_files and not real_files:
        print(
            "\nWARNING: training on SYNTHETIC data only. This model is for "
            "pipeline testing (does the daemon load and run a model correctly) "
            "-- it has NOT learned anything about real ransomware behavior. "
            "Do not use it to produce any number that goes in your report.\n"
        )

    return combined


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--classifier", default="xgboost", choices=["random_forest", "xgboost"])
    ap.add_argument("--include-synthetic", action="store_true",
                     help="also train on results/raw/synthetic_traces_*.csv "
                          "(pipeline-testing only, see warning above)")
    ap.add_argument("--out", default="results/processed/xgb_model.joblib")
    args = ap.parse_args()

    df = load_traces(args.include_synthetic)

    min_class_count = df["label"].value_counts().min()
    if min_class_count < 20:
        print(
            f"\nWARNING: smallest class has only {min_class_count} rows. "
            "Collect more data (longer --duration, more --seed values) for "
            "that class before trusting this model's results.\n"
        )

    clf = build_classifier(args.classifier)
    clf.fit(df, df["label"])
    clf.save(args.out)
    print(f"Saved trained {args.classifier} model to {args.out}")


if __name__ == "__main__":
    main()
