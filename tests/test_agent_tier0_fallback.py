"""
Unit tests for Tier-0-only graceful degradation and structured logging.
"""
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from adaptshield.detection.tier1_bridge import is_tier1_available, get_tier1_status, Tier1Tracer
from adaptshield.daemon import AdaptShieldDaemon
from adaptshield.config import AdaptShieldConfig
from adaptshield.logging.alert_logger import AlertLogger
from adaptshield.detection.feature_aggregator import FeatureAggregator, build_feature_row


def test_tier1_status_reporting():
    st = get_tier1_status()
    assert "available" in st
    assert "mode" in st
    if not st["available"]:
        assert st["mode"] == "tier0_fallback"
        assert st["error"] is not None


def test_tier1_tracer_raises_when_bcc_missing():
    if not is_tier1_available():
        with pytest.raises(RuntimeError) as exc_info:
            Tier1Tracer()
        assert "requires BCC" in str(exc_info.value)


def test_daemon_tier0_graceful_fallback():
    # Force use_tier1=True and verify daemon degrades to Tier-0 without crashing
    cfg = AdaptShieldConfig()
    cfg.detection.use_tier1 = True

    daemon = AdaptShieldDaemon.from_config(cfg, dry_run=True)
    assert daemon is not None
    # On environments without BCC, tier1 should be None and tier1_available should be False
    if not is_tier1_available():
        assert daemon.tier1 is None
        assert daemon.tier1_available is False


def test_tier0_features_produce_valid_rows_without_tier1():
    aggregator = FeatureAggregator(window_seconds=2.0)
    tier0_snap = {
        1001: {
            "pid": 1001,
            "window_s": 2.0,
            "mod_rate": 5.0,
            "rename_rate": 0.0,
            "create_del_rate": 1.0,
            "event_count": 12,
            "concentration_gini": 0.15,
        }
    }
    # No tier-1 events added
    rows = aggregator.build_rows(tier0_snap)
    assert len(rows) == 1
    row = rows[0]
    assert row["pid"] == 1001
    assert row["mod_rate"] == 5.0
    # Tier-1 columns should exist and be NaN
    import numpy as np
    assert np.isnan(row["t1_mean_entropy"])
    assert np.isnan(row["t1_write_rate"])


def test_alert_logger_structured_output():
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        tmp_log = f.name

    try:
        logger = AlertLogger(tmp_log)
        logger.log("alert_critical", pid=4242, risk_ewma=0.92, evidence={"mod_rate": 100.0})
        logger.log("containment", pid=4242, policy="immediate", rolled_back=True, files_at_risk=10)

        # Verify JSONL records written
        with open(tmp_log, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) == 2
        import json
        r1 = json.loads(lines[0])
        assert r1["event_type"] == "alert_critical"
        assert r1["pid"] == 4242
        assert r1["risk_ewma"] == 0.92

        r2 = json.loads(lines[1])
        assert r2["event_type"] == "containment"
        assert r2["policy"] == "immediate"
        assert r2["rolled_back"] is True
    finally:
        Path(tmp_log).unlink(missing_ok=True)
