"""
Merges Tier-0 (always-on) features with Tier-1 (escalation-triggered)
features, when available, into a single fixed-width feature vector per
(PID, window). If Tier-1 has not been triggered for a PID, the Tier-1
columns are filled with a documented sentinel (NOT zero -- zero would
look like "confirmed benign write pattern", which is a different thing
from "we never looked"). Use NaN and let the classifier's missing-value
handling (native in XGBoost, imputation for others) treat it correctly.
"""
import math
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "mod_rate", "rename_rate", "create_del_rate", "event_count",
    "concentration_gini",                       # Tier 0
    "t1_write_rate", "t1_mean_entropy", "t1_entropy_std",
    "t1_unlink_rate", "t1_rename_rate", "t1_mean_write_size",
]


def aggregate_tier1(events: list, window_seconds: float) -> dict:
    if not events:
        return {c: np.nan for c in FEATURE_COLUMNS if c.startswith("t1_")}
    writes = [e for e in events if e["syscall"] == 0]
    unlinks = [e for e in events if e["syscall"] == 3]
    renames = [e for e in events if e["syscall"] == 2]
    entropies = [e["entropy"] for e in writes if e["entropy"] is not None]
    sizes = [e["arg_size"] for e in writes]
    return {
        "t1_write_rate": len(writes) / window_seconds,
        "t1_mean_entropy": float(np.mean(entropies)) if entropies else np.nan,
        "t1_entropy_std": float(np.std(entropies)) if entropies else np.nan,
        "t1_unlink_rate": len(unlinks) / window_seconds,
        "t1_rename_rate": len(renames) / window_seconds,
        "t1_mean_write_size": float(np.mean(sizes)) if sizes else np.nan,
    }


def build_feature_row(pid: int, tier0_features: dict, tier1_events: list,
                       window_seconds: float, label: str | None = None) -> dict:
    row = {"pid": pid}
    row.update({k: tier0_features.get(k, np.nan) for k in
                ["mod_rate", "rename_rate", "create_del_rate",
                 "event_count", "concentration_gini"]})
    row.update(aggregate_tier1(tier1_events, window_seconds))
    if label is not None:
        row["label"] = label  # "benign" | "backup" | "oltp" | "ransomware"
    return row


class FeatureAggregator:
    """Stateful aggregator used by the live daemon: buffers Tier-1 events
    per PID between Tier-0 snapshot calls, then clears the buffer once
    consumed, so events are never double-counted across windows."""

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._tier1_buffer: dict[int, list] = defaultdict(list)

    def add_tier1_events(self, events: list):
        for e in events:
            self._tier1_buffer[e["pid"]].append(e)

    def build_rows(self, tier0_snapshot: dict) -> list[dict]:
        rows = []
        for pid, feats in tier0_snapshot.items():
            t1_events = self._tier1_buffer.pop(pid, [])
            rows.append(build_feature_row(pid, feats, t1_events, self.window_seconds))
        return rows
