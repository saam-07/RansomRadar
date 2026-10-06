import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import accuracy_score

from adaptshield.feature_aggregator import FEATURE_COLUMNS
from scripts.make_datasets import (
    SCHEMA_COLUMNS,
    generate_trace_dataset,
    compute_sha256,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RAW_DIR = DATA_DIR / "raw"
SCENARIOS_DIR = DATA_DIR / "scenarios"


@pytest.fixture(scope="module")
def dataset_splits():
    splits = {}
    for name in ["train", "val", "test", "hard_test"]:
        path = RAW_DIR / f"traces_{name}.csv"
        assert path.exists(), f"Missing split file: {path}"
        splits[name] = pd.read_csv(path)
    return splits


def test_schema_matches_feature_columns(dataset_splits):
    """Schema must contain FEATURE_COLUMNS plus the required metadata columns."""
    expected_meta = ["pid", "run_id", "scenario", "label", "window_idx", "timestamp", "source"]
    for col in FEATURE_COLUMNS:
        assert col in SCHEMA_COLUMNS

    for col in expected_meta:
        assert col in SCHEMA_COLUMNS

    for name, df in dataset_splits.items():
        assert list(df.columns) == SCHEMA_COLUMNS, f"Column mismatch in {name}"
        assert set(df["source"].unique()) == {"synthetic"}, f"Non-synthetic source found in {name}"
        assert set(df["label"].unique()).issubset({"benign", "backup", "oltp", "ransomware"})


def test_zero_run_id_overlap_across_splits(dataset_splits):
    """Zero run_id overlap across all splits (split by run_id, never by row)."""
    split_runs = {name: set(df["run_id"].unique()) for name, df in dataset_splits.items()}

    names = list(split_runs.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            overlap = split_runs[a].intersection(split_runs[b])
            assert len(overlap) == 0, f"Found run_id overlap between {a} and {b}: {overlap}"


def test_reproducibility_same_seed_gives_same_sha256():
    """Generating traces with the same seed must produce identical data and sha256."""
    tr1, val1, te1, hte1 = generate_trace_dataset(seed=42)
    tr2, val2, te2, hte2 = generate_trace_dataset(seed=42)

    pd.testing.assert_frame_equal(tr1, tr2)
    pd.testing.assert_frame_equal(val1, val2)
    pd.testing.assert_frame_equal(te1, te2)
    pd.testing.assert_frame_equal(hte1, hte2)


def test_single_feature_threshold_not_near_perfect(dataset_splits):
    """A single-feature threshold must NOT reach near-perfect accuracy (e.g. >= 98%)."""
    for name, df in dataset_splits.items():
        y_true = (df["label"] == "ransomware").astype(int)
        for col in FEATURE_COLUMNS:
            vals = df[col].dropna()
            if len(vals) == 0:
                continue
            for q in np.linspace(0.05, 0.95, 20):
                thresh = vals.quantile(q)
                pred = (df[col].fillna(-1) >= thresh).astype(int)
                acc = accuracy_score(y_true, pred)
                assert acc < 0.97, f"Feature {col} in {name} is trivially separable at {thresh}: acc={acc:.4f}"


def test_class_counts_match_manifest(dataset_splits):
    """Row counts, class distributions, and SHA256 hashes must strictly match manifest.json."""
    manifest_path = DATA_DIR / "manifest.json"
    assert manifest_path.exists(), "data/manifest.json does not exist"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    for name, df in dataset_splits.items():
        assert name in manifest["splits"], f"Split {name} missing in manifest"
        meta = manifest["splits"][name]

        # Check row counts
        assert len(df) == meta["row_count"]
        assert df["run_id"].nunique() == meta["run_count"]

        # Check class counts
        actual_counts = df["label"].value_counts().to_dict()
        assert actual_counts == meta["class_counts"]

        # Check sha256 checksum
        csv_path = RAW_DIR / f"traces_{name}.csv"
        actual_sha = compute_sha256(csv_path)
        assert actual_sha == meta["sha256"]


def test_hard_test_contains_held_out_scenarios(dataset_splits):
    """traces_hard_test.csv must contain attack variants NOT present in train or val."""
    train_val_scenarios = set(dataset_splits["train"]["scenario"].unique()).union(
        set(dataset_splits["val"]["scenario"].unique())
    )
    hard_scenarios = set(dataset_splits["hard_test"]["scenario"].unique())

    # slow_and_low_ransomware and mixed_chaos are held out from train/val
    assert "slow_and_low_ransomware" in hard_scenarios
    assert "slow_and_low_ransomware" not in train_val_scenarios


def test_unescalated_processes_have_nan_tier1(dataset_splits):
    """Processes that never trigger Tier-1 escalation must have NaN for all Tier-1 columns."""
    t1_cols = [c for c in FEATURE_COLUMNS if c.startswith("t1_")]
    train_df = dataset_splits["train"]

    # Benign processes should contain many unescalated windows
    benign_df = train_df[train_df["label"] == "benign"]
    nan_rows = benign_df[t1_cols].isna().all(axis=1)
    assert nan_rows.sum() > 0, "No unescalated benign windows found"
    assert nan_rows.mean() > 0.60, f"Expected >60% unescalated benign windows, got {nan_rows.mean():.2%}"


def test_scenarios_json_definitions_exist():
    """All 8 required benchmark scenarios must exist in data/scenarios/ and validate."""
    required_ids = [
        "normal_workday",
        "nightly_backup",
        "oltp_database",
        "fast_ransomware",
        "slow_and_low_ransomware",
        "intermittent_ransomware",
        "partial_encryption",
        "mixed_chaos",
    ]
    for sc_id in required_ids:
        path = SCENARIOS_DIR / f"{sc_id}.json"
        assert path.exists(), f"Scenario {sc_id}.json missing"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["id"] == sc_id
        assert "processes" in data
        assert "parameters" in data
        assert "expected_outcome" in data
