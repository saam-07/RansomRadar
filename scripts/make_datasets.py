#!/usr/bin/env python3
"""
AdaptShield Dataset Generator
=============================
Generates reproducible synthetic feature traces and scenario definitions
for the AdaptShield ransomware detection & containment engine.

Requirements addressed:
- Strict schema: FEATURE_COLUMNS from adaptshield.feature_aggregator + metadata columns.
- Realistic class overlap (backup vs ransomware, oltp vs fast ransomware).
- Realistic Tier-1 escalation dynamics (unescalated processes have NaN for Tier-1).
- Per-run parameter jitter, measurement noise, and correlated features.
- Split strictly by run_id (zero run_id leakage across splits).
- Novel evasion variants held out exclusively in traces_hard_test.csv.
- Reproducible with fixed seeds (deterministic SHA-256).
- Supports imbalanced mode (e.g., 99.9% benign) for false-alarm rate testing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pandas as pd

from adaptshield.feature_aggregator import FEATURE_COLUMNS

SCHEMA_COLUMNS = [
    "pid",
    "run_id",
    "scenario",
    "label",
    "window_idx",
    "timestamp",
    "source",
] + FEATURE_COLUMNS

SCHEMA_VERSION = "1.0.0"
GENERATOR_VERSION = "1.0.0"


def generate_scenarios(scenarios_dir: Path) -> List[Dict[str, Any]]:
    """Defines and writes the 8 benchmark scenario definitions to JSON files."""
    scenarios_dir.mkdir(parents=True, exist_ok=True)

    scenarios = [
        {
            "id": "normal_workday",
            "name": "Normal Workday",
            "description": "Standard developer and office workstation activity: text editing, git status, builds, and idle pauses.",
            "family": "benign",
            "variant": "office_worker",
            "expected_outcome": "no_containment",
            "duration_windows": 20,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 1042,
                    "name": "code_editor",
                    "role": "benign_editor",
                    "behavior": "low_mod_sporadic",
                    "escalation_expected": False,
                },
                {
                    "pid": 1088,
                    "name": "git_status",
                    "role": "benign_vcs",
                    "behavior": "read_heavy",
                    "escalation_expected": False,
                },
            ],
            "parameters": {
                "mod_rate_mean": 3.5,
                "rename_rate_mean": 0.4,
                "create_del_rate_mean": 0.3,
                "entropy_mean": 3.8,
                "gini_mean": 0.18,
            },
        },
        {
            "id": "nightly_backup",
            "name": "Nightly Backup",
            "description": "Legitimate high-throughput backup archive job scanning filesystem trees, compressing streams, and writing deduplicated chunk stores.",
            "family": "backup",
            "variant": "backup_restic",
            "expected_outcome": "no_containment",
            "duration_windows": 25,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 2045,
                    "name": "restic",
                    "role": "legitimate_backup",
                    "behavior": "high_throughput_compressed_writes",
                    "escalation_expected": True,
                }
            ],
            "parameters": {
                "mod_rate_mean": 48.0,
                "rename_rate_mean": 0.8,
                "create_del_rate_mean": 8.0,
                "entropy_mean": 6.1,
                "gini_mean": 0.28,
            },
        },
        {
            "id": "oltp_database",
            "name": "OLTP Database",
            "description": "High-concurrency transactional database workload generating continuous write-ahead log (WAL) commits and table page updates.",
            "family": "oltp",
            "variant": "oltp_postgres",
            "expected_outcome": "no_containment",
            "duration_windows": 25,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 3012,
                    "name": "postgres_writer",
                    "role": "database_engine",
                    "behavior": "rapid_in_place_updates",
                    "escalation_expected": True,
                }
            ],
            "parameters": {
                "mod_rate_mean": 35.0,
                "rename_rate_mean": 0.2,
                "create_del_rate_mean": 1.2,
                "entropy_mean": 3.9,
                "gini_mean": 0.22,
            },
        },
        {
            "id": "fast_ransomware",
            "name": "Fast Ransomware Outbreak",
            "description": "Rapid bulk encryption traversing user directories, overwriting file contents with cipher blocks, and replacing file extensions.",
            "family": "ransomware",
            "variant": "fast",
            "expected_outcome": "contained_and_rolled_back",
            "duration_windows": 20,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 4099,
                    "name": "encryptor.elf",
                    "role": "attacker",
                    "behavior": "rapid_bulk_encryption",
                    "escalation_expected": True,
                }
            ],
            "parameters": {
                "mod_rate_mean": 65.0,
                "rename_rate_mean": 32.0,
                "create_del_rate_mean": 2.5,
                "entropy_mean": 7.6,
                "gini_mean": 0.68,
            },
        },
        {
            "id": "slow_and_low_ransomware",
            "name": "Slow-and-Low Ransomware",
            "description": "Stealthy ransomware pacing its encryption rate with deliberate sleep cycles to blend in below volume-based rate alerts.",
            "family": "ransomware",
            "variant": "slow_and_low",
            "expected_outcome": "contained_and_rolled_back",
            "duration_windows": 35,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 5011,
                    "name": "stealth_crypt",
                    "role": "attacker",
                    "behavior": "low_rate_throttled_encryption",
                    "escalation_expected": True,
                }
            ],
            "parameters": {
                "mod_rate_mean": 6.5,
                "rename_rate_mean": 3.0,
                "create_del_rate_mean": 0.8,
                "entropy_mean": 7.4,
                "gini_mean": 0.52,
            },
        },
        {
            "id": "intermittent_ransomware",
            "name": "Intermittent Burst Ransomware",
            "description": "Burst-oriented ransomware encrypting clusters of files at high speed followed by silence to disrupt consecutive detection windows.",
            "family": "ransomware",
            "variant": "intermittent",
            "expected_outcome": "contained_and_rolled_back",
            "duration_windows": 30,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 6023,
                    "name": "burst_locker",
                    "role": "attacker",
                    "behavior": "burst_and_pause_encryption",
                    "escalation_expected": True,
                }
            ],
            "parameters": {
                "mod_rate_mean": 42.0,
                "rename_rate_mean": 18.0,
                "create_del_rate_mean": 1.5,
                "entropy_mean": 7.5,
                "gini_mean": 0.62,
            },
        },
        {
            "id": "partial_encryption",
            "name": "Partial Header Encryption",
            "description": "Evasive ransomware encrypting only header blocks and interleaving plaintext segments to keep file entropy moderate.",
            "family": "ransomware",
            "variant": "partial_encryption",
            "expected_outcome": "contained_and_rolled_back",
            "duration_windows": 25,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 7034,
                    "name": "header_lock",
                    "role": "attacker",
                    "behavior": "partial_chunk_encryption",
                    "escalation_expected": True,
                }
            ],
            "parameters": {
                "mod_rate_mean": 32.0,
                "rename_rate_mean": 8.5,
                "create_del_rate_mean": 1.0,
                "entropy_mean": 6.2,
                "gini_mean": 0.44,
            },
        },
        {
            "id": "mixed_chaos",
            "name": "Mixed Multi-Process Chaos",
            "description": "Concurrent multi-process environment with background developer builds, an active database, and two independent simultaneous ransomware attackers.",
            "family": "ransomware",
            "variant": "mixed_chaos",
            "expected_outcome": "contained_and_rolled_back",
            "duration_windows": 30,
            "window_seconds": 2.0,
            "processes": [
                {
                    "pid": 8001,
                    "name": "dev_worker",
                    "role": "benign",
                    "behavior": "compile_and_test",
                    "escalation_expected": False,
                },
                {
                    "pid": 8002,
                    "name": "db_worker",
                    "role": "oltp",
                    "behavior": "wal_flush",
                    "escalation_expected": True,
                },
                {
                    "pid": 8010,
                    "name": "attacker_alpha",
                    "role": "ransomware",
                    "behavior": "fast_encryption",
                    "escalation_expected": True,
                },
                {
                    "pid": 8020,
                    "name": "attacker_beta",
                    "role": "ransomware",
                    "behavior": "rename_then_encrypt",
                    "escalation_expected": True,
                },
            ],
            "parameters": {
                "mod_rate_mean": 55.0,
                "rename_rate_mean": 24.0,
                "create_del_rate_mean": 3.0,
                "entropy_mean": 7.3,
                "gini_mean": 0.65,
            },
        },
    ]

    for sc in scenarios:
        filepath = scenarios_dir / f"{sc['id']}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sc, f, indent=2)

    return scenarios


def simulate_run_windows(
    run_id: str,
    pid: int,
    label: str,
    scenario: str,
    variant: str,
    n_windows: int,
    rng: np.random.Generator,
    base_timestamp: float = 1728000000.0,
    window_seconds: float = 2.0,
) -> pd.DataFrame:
    """Generates consecutive evaluation windows for a single process run with realistic dynamics."""

    # Per-run parameter jitter (each process session has distinct hardware / workload characteristics)
    jitter = float(rng.normal(1.0, 0.12))
    jitter = max(0.65, min(1.45, jitter))

    rows = []
    current_time = base_timestamp

    for w_idx in range(n_windows):
        # Default Tier-0 & Tier-1 parameters based on class and variant
        is_escalated = False

        if label == "benign":
            mod_base = rng.uniform(0.5, 7.5) * jitter
            if variant == "developer_build" and w_idx in [4, 5, 6, 7]:
                # Burst compile activity
                mod_base += rng.uniform(12.0, 24.0)
            mod_rate = max(0.0, float(mod_base + rng.normal(0, 0.8)))
            rename_rate = max(0.0, float(rng.uniform(0.0, 1.2) + (0.8 if variant == "developer_build" else 0.0)))
            create_del_rate = max(0.0, float(rng.uniform(0.0, 2.0)))
            gini = float(np.clip(rng.uniform(0.05, 0.32) + rng.normal(0, 0.03), 0.02, 0.45))

            # Benign rarely triggers Tier-1 escalation (<8% probability, e.g. during build bursts)
            if mod_rate > 18.0 or rng.random() < 0.05:
                is_escalated = True
                entropy = float(np.clip(rng.uniform(2.5, 4.8) + rng.normal(0, 0.3), 1.8, 5.4))
                entropy_std = float(rng.uniform(0.1, 0.8))
                write_size = float(rng.uniform(300, 4500))

        elif label == "backup":
            # Backup generates heavy sequential writes; overlaps heavily with fast ransomware in mod_rate
            mod_base = rng.uniform(30.0, 75.0) * jitter
            mod_rate = max(5.0, float(mod_base + rng.normal(0, 4.0)))
            rename_rate = max(0.0, float(rng.uniform(0.1, 2.5)))
            create_del_rate = max(0.5, float(rng.uniform(4.0, 22.0) * jitter))
            gini = float(np.clip(rng.uniform(0.18, 0.42) + rng.normal(0, 0.04), 0.10, 0.52))

            # Backup triggers Tier-1 on ~75% of active windows due to mod_rate
            if mod_rate > 25.0 or rng.random() < 0.70:
                is_escalated = True
                # Compressed archives / encrypted chunks produce medium-to-high entropy (5.4 - 6.85)
                # This deliberately overlaps with partial-encryption and mimicry ransomware!
                entropy = float(np.clip(rng.uniform(5.4, 6.85) + rng.normal(0, 0.15), 4.8, 7.1))
                entropy_std = float(rng.uniform(0.15, 0.55))
                write_size = float(rng.uniform(16384, 65536))

        elif label == "oltp":
            # OLTP database updates in-place; overlaps with moderate ransomware in mod_rate
            mod_base = rng.uniform(20.0, 60.0) * jitter
            mod_rate = max(5.0, float(mod_base + rng.normal(0, 3.0)))
            rename_rate = max(0.0, float(rng.uniform(0.0, 0.8)))
            create_del_rate = max(0.0, float(rng.uniform(0.2, 3.5)))
            gini = float(np.clip(rng.uniform(0.12, 0.38) + rng.normal(0, 0.03), 0.08, 0.45))

            if mod_rate > 22.0 or rng.random() < 0.65:
                is_escalated = True
                entropy = float(np.clip(rng.uniform(3.0, 5.6) + rng.normal(0, 0.25), 2.2, 6.0))
                entropy_std = float(rng.uniform(0.2, 0.85))
                write_size = float(rng.uniform(1024, 16384))

        elif label == "ransomware":
            # Distinct attack variant behavior
            if variant == "fast":
                mod_rate = max(20.0, float(rng.uniform(50.0, 95.0) * jitter + rng.normal(0, 5.0)))
                rename_rate = max(5.0, float(rng.uniform(18.0, 48.0) * jitter))
                create_del_rate = max(0.0, float(rng.uniform(1.0, 5.0)))
                gini = float(np.clip(rng.uniform(0.52, 0.82) + rng.normal(0, 0.04), 0.35, 0.95))
                is_escalated = True
                entropy = float(np.clip(rng.uniform(7.2, 7.98) + rng.normal(0, 0.05), 6.9, 8.0))
                entropy_std = float(rng.uniform(0.04, 0.32))
                write_size = float(rng.uniform(2048, 16384))

            elif variant == "slow_and_low":
                # Throttled encryption: rate is deliberately low (overlaps with benign!)
                mod_rate = max(0.5, float(rng.uniform(2.5, 11.5) * jitter + rng.normal(0, 0.8)))
                rename_rate = max(0.0, float(rng.uniform(0.8, 4.2)))
                create_del_rate = max(0.0, float(rng.uniform(0.2, 1.8)))
                gini = float(np.clip(rng.uniform(0.38, 0.68) + rng.normal(0, 0.04), 0.25, 0.78))
                # Only escalates ~55% of windows because mod_rate is low
                is_escalated = rng.random() < 0.60 or w_idx > 8
                if is_escalated:
                    entropy = float(np.clip(rng.uniform(7.0, 7.85) + rng.normal(0, 0.1), 6.5, 7.95))
                    entropy_std = float(rng.uniform(0.08, 0.45))
                    write_size = float(rng.uniform(1024, 8192))

            elif variant == "intermittent":
                # Burst then sleep
                is_burst = (w_idx % 4) in [0, 1]
                if is_burst:
                    mod_rate = max(15.0, float(rng.uniform(35.0, 80.0) * jitter))
                    rename_rate = max(2.0, float(rng.uniform(12.0, 32.0)))
                    create_del_rate = max(0.0, float(rng.uniform(0.5, 3.5)))
                    gini = float(np.clip(rng.uniform(0.48, 0.78), 0.30, 0.88))
                    is_escalated = True
                    entropy = float(np.clip(rng.uniform(7.1, 7.95), 6.8, 8.0))
                    entropy_std = float(rng.uniform(0.06, 0.38))
                    write_size = float(rng.uniform(2048, 16384))
                else:
                    mod_rate = float(rng.uniform(0.0, 2.5))
                    rename_rate = float(rng.uniform(0.0, 0.5))
                    create_del_rate = 0.0
                    gini = float(rng.uniform(0.05, 0.25))
                    is_escalated = False

            elif variant == "partial_encryption":
                # Only encrypts file headers; entropy is moderate (5.6 - 6.8), overlapping with backup!
                mod_rate = max(10.0, float(rng.uniform(22.0, 58.0) * jitter))
                rename_rate = max(1.0, float(rng.uniform(6.0, 22.0)))
                create_del_rate = max(0.0, float(rng.uniform(0.5, 3.0)))
                gini = float(np.clip(rng.uniform(0.32, 0.62), 0.20, 0.72))
                is_escalated = True
                entropy = float(np.clip(rng.uniform(5.6, 6.85) + rng.normal(0, 0.15), 5.2, 7.1))
                entropy_std = float(rng.uniform(0.35, 1.25))
                write_size = float(rng.uniform(1024, 8192))

            elif variant == "rename_then_encrypt":
                # High rename rate prior to writing
                rename_rate = max(15.0, float(rng.uniform(25.0, 72.0) * jitter))
                mod_rate = max(12.0, float(rng.uniform(25.0, 68.0) * jitter))
                create_del_rate = max(0.0, float(rng.uniform(0.5, 4.0)))
                gini = float(np.clip(rng.uniform(0.45, 0.78), 0.30, 0.88))
                is_escalated = True
                entropy = float(np.clip(rng.uniform(7.1, 7.96), 6.8, 8.0))
                entropy_std = float(rng.uniform(0.05, 0.35))
                write_size = float(rng.uniform(2048, 16384))

            elif variant == "delete_original":
                # Writes clone and unlinks original -> high create_del_rate and t1_unlink_rate
                mod_rate = max(15.0, float(rng.uniform(25.0, 65.0) * jitter))
                rename_rate = max(0.0, float(rng.uniform(0.5, 5.0)))
                create_del_rate = max(10.0, float(rng.uniform(15.0, 52.0) * jitter))
                gini = float(np.clip(rng.uniform(0.42, 0.75), 0.28, 0.85))
                is_escalated = True
                entropy = float(np.clip(rng.uniform(7.1, 7.96), 6.7, 8.0))
                entropy_std = float(rng.uniform(0.08, 0.40))
                write_size = float(rng.uniform(2048, 16384))

            elif variant == "mimicry":
                # Mimics backup write sizes (16k - 64k) and moderate rates with padded encryption
                mod_rate = max(15.0, float(rng.uniform(24.0, 52.0) * jitter))
                rename_rate = max(0.0, float(rng.uniform(0.5, 4.0)))
                create_del_rate = max(1.0, float(rng.uniform(3.0, 15.0)))
                gini = float(np.clip(rng.uniform(0.22, 0.52), 0.15, 0.60))
                is_escalated = True
                # Entropy around 6.1 - 7.15 (heavy overlap with compressed backup!)
                entropy = float(np.clip(rng.uniform(6.1, 7.15) + rng.normal(0, 0.15), 5.7, 7.4))
                entropy_std = float(rng.uniform(0.20, 0.65))
                write_size = float(rng.uniform(16384, 65536))

            else:
                raise ValueError(f"Unknown ransomware variant: {variant}")
        else:
            raise ValueError(f"Unknown class label: {label}")

        # Compute aggregate event count
        total_events = int((mod_rate + rename_rate + create_del_rate) * window_seconds + rng.integers(1, 12))
        event_count = max(1, total_events)

        # Correlated Tier-1 values (or NaN if unescalated)
        if is_escalated:
            t1_write_rate = max(0.0, float(mod_rate * rng.uniform(0.88, 1.05) + rng.normal(0, 0.5)))
            t1_mean_entropy = float(entropy)
            t1_entropy_std = float(entropy_std)
            if variant == "delete_original":
                t1_unlink_rate = max(0.0, float(create_del_rate * rng.uniform(0.70, 0.95)))
            else:
                t1_unlink_rate = max(0.0, float(create_del_rate * rng.uniform(0.05, 0.35)))
            t1_rename_rate = max(0.0, float(rename_rate * rng.uniform(0.85, 1.08)))
            t1_mean_write_size = float(write_size)
        else:
            t1_write_rate = np.nan
            t1_mean_entropy = np.nan
            t1_entropy_std = np.nan
            t1_unlink_rate = np.nan
            t1_rename_rate = np.nan
            t1_mean_write_size = np.nan

        row = {
            "pid": pid,
            "run_id": run_id,
            "scenario": scenario,
            "label": label,
            "window_idx": w_idx,
            "timestamp": round(current_time, 2),
            "source": "synthetic",
            "mod_rate": round(mod_rate, 4),
            "rename_rate": round(rename_rate, 4),
            "create_del_rate": round(create_del_rate, 4),
            "event_count": int(event_count),
            "concentration_gini": round(gini, 4),
            "t1_write_rate": round(t1_write_rate, 4) if not np.isnan(t1_write_rate) else np.nan,
            "t1_mean_entropy": round(t1_mean_entropy, 4) if not np.isnan(t1_mean_entropy) else np.nan,
            "t1_entropy_std": round(t1_entropy_std, 4) if not np.isnan(t1_entropy_std) else np.nan,
            "t1_unlink_rate": round(t1_unlink_rate, 4) if not np.isnan(t1_unlink_rate) else np.nan,
            "t1_rename_rate": round(t1_rename_rate, 4) if not np.isnan(t1_rename_rate) else np.nan,
            "t1_mean_write_size": round(t1_mean_write_size, 2) if not np.isnan(t1_mean_write_size) else np.nan,
        }
        rows.append(row)
        current_time += window_seconds

    return pd.DataFrame(rows)[SCHEMA_COLUMNS]


def generate_trace_dataset(
    seed: int = 42,
    windows_per_run: int = 15,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Generates standard runs and splits them by run_id into train, val, and test.
    Generates held-out hard test runs containing variants never present in train or val.
    """
    rng = np.random.default_rng(seed)

    # Standard variants pool for train/val/test
    standard_specs = [
        # (label, scenario, variant, n_runs)
        ("benign", "normal_workday", "office_worker", 70),
        ("benign", "normal_workday", "developer_build", 50),
        ("backup", "nightly_backup", "backup_tar", 40),
        ("backup", "nightly_backup", "backup_restic", 40),
        ("oltp", "oltp_database", "oltp_postgres", 45),
        ("oltp", "oltp_database", "oltp_mysql", 35),
        ("ransomware", "fast_ransomware", "fast", 30),
        ("ransomware", "intermittent_ransomware", "intermittent", 25),
        ("ransomware", "partial_encryption", "partial_encryption", 25),
        ("ransomware", "fast_ransomware", "rename_then_encrypt", 20),
        ("ransomware", "fast_ransomware", "delete_original", 20),
    ]

    # Held-out variants ONLY for traces_hard_test.csv (never in train or val)
    hard_specs = [
        # Novel stealth and mimicry ransomware variants
        ("ransomware", "slow_and_low_ransomware", "slow_and_low", 30),
        ("ransomware", "mixed_chaos", "mimicry", 30),
        # Challenging benign/backup edge cases
        ("benign", "normal_workday", "developer_build", 20),
        ("backup", "nightly_backup", "backup_restic", 20),
        ("oltp", "oltp_database", "oltp_postgres", 20),
    ]

    run_counter = 1000
    standard_runs_by_class: Dict[str, List[pd.DataFrame]] = {
        "benign": [],
        "backup": [],
        "oltp": [],
        "ransomware": [],
    }

    base_time = 1728000000.0

    for label, scenario, variant, n_runs in standard_specs:
        for _ in range(n_runs):
            run_id = f"run_{run_counter}"
            pid = int(rng.integers(1050, 55000))
            run_df = simulate_run_windows(
                run_id=run_id,
                pid=pid,
                label=label,
                scenario=scenario,
                variant=variant,
                n_windows=windows_per_run,
                rng=rng,
                base_timestamp=base_time,
            )
            standard_runs_by_class[label].append(run_df)
            run_counter += 1
            base_time += 100.0

    # Stratified split by run_id (60% train, 20% val, 20% test)
    train_runs: List[pd.DataFrame] = []
    val_runs: List[pd.DataFrame] = []
    test_runs: List[pd.DataFrame] = []

    for label, runs in standard_runs_by_class.items():
        rng.shuffle(runs)
        n = len(runs)
        n_train = int(n * 0.60)
        n_val = int(n * 0.20)
        train_runs.extend(runs[:n_train])
        val_runs.extend(runs[n_train : n_train + n_val])
        test_runs.extend(runs[n_train + n_val :])

    train_df = pd.concat(train_runs, ignore_index=True)
    val_df = pd.concat(val_runs, ignore_index=True)
    test_df = pd.concat(test_runs, ignore_index=True)

    # Generate held-out hard test runs
    hard_runs: List[pd.DataFrame] = []
    for label, scenario, variant, n_runs in hard_specs:
        for _ in range(n_runs):
            run_id = f"run_{run_counter}"
            pid = int(rng.integers(1050, 55000))
            run_df = simulate_run_windows(
                run_id=run_id,
                pid=pid,
                label=label,
                scenario=scenario,
                variant=variant,
                n_windows=windows_per_run,
                rng=rng,
                base_timestamp=base_time,
            )
            hard_runs.append(run_df)
            run_counter += 1
            base_time += 100.0

    hard_test_df = pd.concat(hard_runs, ignore_index=True)

    return train_df, val_df, test_df, hard_test_df


def generate_imbalanced_dataset(
    seed: int = 42,
    ratio_benign: float = 0.999,
    total_runs: int = 500,
    windows_per_run: int = 15,
) -> pd.DataFrame:
    """Generates an imbalanced dataset (e.g. 99.9% benign) for false-alarm rate calibration."""
    rng = np.random.default_rng(seed + 999)
    runs: List[pd.DataFrame] = []
    base_time = 1729000000.0

    n_ransomware = max(1, int(round(total_runs * (1.0 - ratio_benign))))
    n_benign = total_runs - n_ransomware

    run_counter = 8000
    for _ in range(n_benign):
        run_id = f"run_imb_{run_counter}"
        pid = int(rng.integers(1050, 55000))
        variant = "office_worker" if rng.random() < 0.8 else "developer_build"
        runs.append(
            simulate_run_windows(
                run_id, pid, "benign", "normal_workday", variant, windows_per_run, rng, base_time
            )
        )
        run_counter += 1
        base_time += 100.0

    for _ in range(n_ransomware):
        run_id = f"run_imb_{run_counter}"
        pid = int(rng.integers(1050, 55000))
        runs.append(
            simulate_run_windows(
                run_id, pid, "ransomware", "fast_ransomware", "fast", windows_per_run, rng, base_time
            )
        )
        run_counter += 1
        base_time += 100.0

    return pd.concat(runs, ignore_index=True)


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def write_manifest_and_card(
    data_dir: Path,
    splits_meta: Dict[str, Any],
    seed: int,
) -> None:
    """Writes data/manifest.json and data/DATASET_CARD.md."""
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "feature_columns": FEATURE_COLUMNS,
        "schema_columns": SCHEMA_COLUMNS,
        "splits": splits_meta,
        "total_rows": sum(s["row_count"] for s in splits_meta.values()),
    }

    manifest_path = data_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    card_path = data_dir / "DATASET_CARD.md"
    card_content = f"""# AdaptShield Dataset Card

## 1. Summary
This dataset contains synthetic feature traces designed to benchmark the **AdaptShield** ransomware detection and containment engine. It models the behavioral characteristics of benign developer workloads, legitimate high-volume backup processes, transactional OLTP database engines, and multiple evasive ransomware variants.

> **CRITICAL DISCLAIMER: SYNTHETIC DATA NOTICE**  
> All records in this dataset are generated from behavioral models and labeled as `source: synthetic`.  
> Synthetic-trained models demonstrate pipeline and risk-scoring functionality; performance on synthetic traces does **NOT** represent real-world detection efficacy or replace validation against real kernel instrumentation.

---

## 2. Schema Specification (Version {SCHEMA_VERSION})

| Column | Type | Role | Description |
|---|---|---|---|
| `pid` | int | Metadata | Operating system process identifier |
| `run_id` | str | Metadata | Unique process session run identifier (split grouping key) |
| `scenario` | str | Metadata | Benchmark scenario name |
| `label` | str | Target | Class: `benign`, `backup`, `oltp`, `ransomware` |
| `window_idx` | int | Temporal | Sequential 2-second window index within the run |
| `timestamp` | float | Temporal | Epoch timestamp of window snapshot |
| `source` | str | Provenance | Provenance tag (`synthetic`) |
| `mod_rate` | float | Tier-0 | File modification rate (events/sec) |
| `rename_rate` | float | Tier-0 | File rename rate (events/sec) |
| `create_del_rate` | float | Tier-0 | File create and delete rate (events/sec) |
| `event_count` | int | Tier-0 | Total raw fanotify events in window |
| `concentration_gini` | float | Tier-0 | Gini concentration coefficient of touched files |
| `t1_write_rate` | float | Tier-1 | eBPF traced sys_write rate (`NaN` if never escalated) |
| `t1_mean_entropy` | float | Tier-1 | Mean Shannon byte entropy of write buffers (`NaN` if never escalated) |
| `t1_entropy_std` | float | Tier-1 | Standard deviation of byte entropy (`NaN` if never escalated) |
| `t1_unlink_rate` | float | Tier-1 | eBPF traced sys_unlink rate (`NaN` if never escalated) |
| `t1_rename_rate` | float | Tier-1 | eBPF traced sys_rename rate (`NaN` if never escalated) |
| `t1_mean_write_size` | float | Tier-1 | Mean payload size of write syscalls (`NaN` if never escalated) |

---

## 3. Dataset Splits & Class Distributions

| Split | File | Distinct Runs | Row Count | Benign | Backup | OLTP | Ransomware | SHA-256 Checksum |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
"""
    for split_name, meta in splits_meta.items():
        cc = meta["class_counts"]
        card_content += (
            f"| `{split_name}` | `{meta['filename']}` | {meta['run_count']} | {meta['row_count']} "
            f"| {cc.get('benign', 0)} | {cc.get('backup', 0)} | {cc.get('oltp', 0)} | {cc.get('ransomware', 0)} "
            f"| `{meta['sha256'][:16]}...` |\n"
        )

    card_content += f"""
### Split Integrity
- **Grouping:** All splits are grouped strictly by `run_id`. Zero `run_id` overlap exists across train, val, and test splits.
- **Held-out Hard Test:** `traces_hard_test.csv` contains evasion tactics (`slow_and_low`, `mimicry`) that **never appear in train or validation sets**, testing model generalization against unseen attack patterns.

---

## 4. Realistic Class Overlap Design
To avoid artificial separability:
1. **Backup vs. Ransomware:** Backup jobs compress archives, producing high `mod_rate` (25–85 ops/sec) and high entropy (5.4–6.85), overlapping with partial-encryption and mimicry ransomware.
2. **OLTP vs. Ransomware:** Database engines write WAL logs at high frequencies (15–65 ops/sec) with moderate entropy, overlapping with throttled and intermittent ransomware.
3. **Slow-and-Low Ransomware:** Emits low modification rates (2–12 ops/sec) to blend into benign background developer activity.
4. **Tier-1 Escalation Sentinels:** Unescalated processes preserve documented `NaN` values across all `t1_*` features, matching the real AdaptShield dual-tier operational architecture.

---

## 5. Generator Details
- **Generator Version:** `{GENERATOR_VERSION}`
- **Random Seed:** `{seed}` (fixed master seed for bitwise reproducibility)
- **Generated At:** `{datetime.now(timezone.utc).isoformat()}`
"""

    with open(card_path, "w", encoding="utf-8") as f:
        f.write(card_content)


def main():
    parser = argparse.ArgumentParser(description="Generate AdaptShield datasets and scenarios.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    parser.add_argument("--out-dir", type=str, default="data", help="Root data output directory.")
    parser.add_argument("--windows-per-run", type=int, default=15, help="Windows per process run.")
    parser.add_argument("--imbalanced", action="store_true", help="Also generate 99.9% benign imbalanced trace.")
    parser.add_argument("--imbalanced-ratio", type=float, default=0.999, help="Ratio of benign traffic in imbalanced mode.")
    args = parser.parse_args()

    data_dir = Path(args.out_dir)
    raw_dir = data_dir / "raw"
    scenarios_dir = data_dir / "scenarios"
    raw_dir.mkdir(parents=True, exist_ok=True)
    scenarios_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/4] Generating scenario definitions in {scenarios_dir}...")
    generate_scenarios(scenarios_dir)

    print(f"[2/4] Generating trace splits with seed={args.seed}...")
    train_df, val_df, test_df, hard_test_df = generate_trace_dataset(
        seed=args.seed, windows_per_run=args.windows_per_run
    )

    splits = {
        "train": (raw_dir / "traces_train.csv", train_df),
        "val": (raw_dir / "traces_val.csv", val_df),
        "test": (raw_dir / "traces_test.csv", test_df),
        "hard_test": (raw_dir / "traces_hard_test.csv", hard_test_df),
    }

    if args.imbalanced:
        print(f"[2b/4] Generating imbalanced test trace (ratio={args.imbalanced_ratio})...")
        imb_df = generate_imbalanced_dataset(
            seed=args.seed,
            ratio_benign=args.imbalanced_ratio,
            windows_per_run=args.windows_per_run,
        )
        splits["imbalanced_test"] = (raw_dir / "traces_imbalanced_test.csv", imb_df)

    print(f"[3/4] Writing trace CSV files to {raw_dir}...")
    splits_meta: Dict[str, Any] = {}

    for name, (path, df) in splits.items():
        df.to_csv(path, index=False)
        sha256 = compute_sha256(path)
        class_counts = df["label"].value_counts().to_dict()
        run_count = df["run_id"].nunique()
        splits_meta[name] = {
            "filename": str(path.relative_to(data_dir)).replace("\\", "/"),
            "sha256": sha256,
            "row_count": len(df),
            "run_count": run_count,
            "class_counts": class_counts,
            "scenarios": sorted(df["scenario"].unique().tolist()),
        }
        print(f"  -> {path.name}: {len(df)} rows, {run_count} runs, sha256={sha256[:12]}...")

    print(f"[4/4] Writing manifest and dataset card to {data_dir}...")
    write_manifest_and_card(data_dir, splits_meta, args.seed)
    print("Done! Datasets successfully generated.")


if __name__ == "__main__":
    main()
