"""
Generates a SYNTHETIC feature dataset with the same columns
generate_labeled_traces.py produces, so you can test train_model.py and
daemon.py's ML classifier path end-to-end BEFORE you have real kernel
traces (e.g., while still debugging fanotify/eBPF on your VM).

This is NOT a real dataset. It is hand-built from simple statistical
assumptions about what "should" separate ransomware from benign/backup/
oltp traffic (higher mod/rename rate, higher entropy). Do not report any
number produced by a model trained only on this data -- it exists purely
to let you verify "does the plumbing work" independently of "is the
kernel instrumentation collecting correctly."

Usage:
    python3 dataset/make_synthetic_bootstrap.py --rows-per-class 300 \
        --out results/raw/synthetic_traces_bootstrap.csv
"""
import argparse

import numpy as np
import pandas as pd

from adaptshield.feature_aggregator import FEATURE_COLUMNS


def make_class(label: str, n: int, rng: np.random.Generator) -> pd.DataFrame:
    if label == "benign":
        base = dict(mod_rate=(0, 3), rename_rate=(0, 0.5), create_del_rate=(0, 0.5),
                    concentration_gini=(0.0, 0.2), t1_write_rate=(0, 3),
                    t1_mean_entropy=(2.0, 4.5), t1_unlink_rate=(0, 0.2),
                    t1_rename_rate=(0, 0.3), t1_mean_write_size=(200, 4000))
    elif label == "backup":
        base = dict(mod_rate=(20, 60), rename_rate=(0, 1), create_del_rate=(5, 20),
                    concentration_gini=(0.1, 0.35), t1_write_rate=(20, 60),
                    t1_mean_entropy=(3.0, 5.5), t1_unlink_rate=(0, 1),
                    t1_rename_rate=(0, 1), t1_mean_write_size=(4000, 60000))
    elif label == "oltp":
        base = dict(mod_rate=(10, 40), rename_rate=(0, 0.5), create_del_rate=(0, 5),
                    concentration_gini=(0.05, 0.25), t1_write_rate=(10, 40),
                    t1_mean_entropy=(1.5, 3.5), t1_unlink_rate=(0, 0.5),
                    t1_rename_rate=(0, 0.2), t1_mean_write_size=(100, 2000))
    elif label == "ransomware":
        base = dict(mod_rate=(40, 100), rename_rate=(20, 60), create_del_rate=(0, 5),
                    concentration_gini=(0.5, 0.95), t1_write_rate=(40, 100),
                    t1_mean_entropy=(7.0, 8.0), t1_unlink_rate=(0, 2),
                    t1_rename_rate=(20, 60), t1_mean_write_size=(1000, 20000))
    else:
        raise ValueError(label)

    data = {}
    for col in FEATURE_COLUMNS:
        if col == "event_count":
            data[col] = rng.integers(1, 200, size=n)
        elif col in base:
            lo, hi = base[col]
            data[col] = rng.uniform(lo, hi, size=n)
        else:
            data[col] = rng.uniform(0, 1, size=n)  # any column not explicitly modeled
    data["t1_entropy_std"] = rng.uniform(0.1, 1.5, size=n)
    df = pd.DataFrame(data)
    df["pid"] = rng.integers(1000, 60000, size=n)
    df["label"] = label
    return df


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rows-per-class", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="results/raw/synthetic_traces_bootstrap.csv")
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    frames = [make_class(label, args.rows_per_class, rng)
              for label in ["benign", "backup", "oltp", "ransomware"]]
    df = pd.concat(frames, ignore_index=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} SYNTHETIC rows to {args.out}")
    print("Reminder: this data is for pipeline testing only, see module docstring.")


if __name__ == "__main__":
    main()
