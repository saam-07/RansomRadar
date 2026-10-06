import math

from adaptshield.feature_aggregator import aggregate_tier1, build_feature_row
from adaptshield.math_utils import shannon_entropy


def test_entropy_of_uniform_random_bytes_is_high():
    data = bytes(range(256))  # perfectly uniform distribution over byte values
    e = shannon_entropy(data)
    assert e > 7.9  # max possible is 8.0 bits


def test_entropy_of_constant_bytes_is_zero():
    data = bytes([65] * 1000)  # all 'A'
    e = shannon_entropy(data)
    assert e == 0.0


def test_aggregate_tier1_empty_events_returns_nan_sentinels():
    feats = aggregate_tier1([], window_seconds=2.0)
    assert math.isnan(feats["t1_mean_entropy"])


def test_aggregate_tier1_computes_rates():
    events = [
        {"pid": 1, "syscall": 0, "arg_size": 100, "entropy": 7.5, "ts_ns": 0},
        {"pid": 1, "syscall": 0, "arg_size": 100, "entropy": 7.9, "ts_ns": 1},
        {"pid": 1, "syscall": 3, "arg_size": 0, "entropy": None, "ts_ns": 2},
    ]
    feats = aggregate_tier1(events, window_seconds=2.0)
    assert feats["t1_write_rate"] == 1.0  # 2 writes / 2s
    assert feats["t1_unlink_rate"] == 0.5


def test_build_feature_row_shape():
    tier0 = {"mod_rate": 1.0, "rename_rate": 0.0, "create_del_rate": 0.0,
             "event_count": 5, "concentration_gini": 0.2}
    row = build_feature_row(pid=42, tier0_features=tier0, tier1_events=[],
                             window_seconds=2.0, label="benign")
    assert row["pid"] == 42
    assert row["label"] == "benign"
    assert "t1_mean_entropy" in row
