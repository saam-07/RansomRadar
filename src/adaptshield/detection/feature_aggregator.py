"""
Merges Tier-0 (always-on) features with Tier-1 (escalation-triggered) features.
If Tier-1 has not been triggered, Tier-1 columns use np.nan sentinels.
"""
from collections import defaultdict

import numpy as np

FEATURE_COLUMNS = [
    "mod_rate", "rename_rate", "create_del_rate", "event_count",
    "concentration_gini",                       # Tier 0
    "t1_write_rate", "t1_mean_entropy", "t1_entropy_std",
    "t1_unlink_rate", "t1_rename_rate", "t1_mean_write_size",
]


def aggregate_tier1(events: list, window_seconds: float) -> dict:
    if not events:
        return {c: np.nan for c in FEATURE_COLUMNS if c.startswith("t1_")}
    writes = [e for e in events if e.get("syscall") == 0]
    unlinks = [e for e in events if e.get("syscall") == 3]
    renames = [e for e in events if e.get("syscall") == 2]
    entropies = [e["entropy"] for e in writes if e.get("entropy") is not None]
    sizes = [e["arg_size"] for e in writes if "arg_size" in e]
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
        row["label"] = label
    return row


class FeatureAggregator:
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
