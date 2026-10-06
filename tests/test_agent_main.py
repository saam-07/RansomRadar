"""
Unit tests for AdaptShield agent main loop, modes, ML auto-selection, and signal handling.
"""
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from adaptshield.config import AdaptShieldConfig
from adaptshield.daemon import AdaptShieldDaemon
from adaptshield.ml.classifier import RuleBasedClassifier
from adaptshield.ml.explain import explain_alert
from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.schema import FEATURE_COLUMNS
from adaptshield.ml.selector import select_classifier
from adaptshield.mode import ModeManager
from adaptshield.telemetry import TelemetryWriter


def test_classifier_selection_fallback_when_registry_missing():
    cfg = AdaptShieldConfig()
    cfg.classifier.mode = "auto"
    cfg.classifier.registry_dir = "nonexistent_dir_for_test"

    clf, meta = select_classifier(cfg)
    assert isinstance(clf, RuleBasedClassifier)
    assert meta["name"] == "rule_based"
    assert meta["fallback_used"] is True


def test_synthetic_model_guard_blocks_containment_in_protect_mode():
    with tempfile.TemporaryDirectory() as tmp_dir:
        reg_dir = Path(tmp_dir) / "registry"
        reg_dir.mkdir()

        # Mock a synthetic model in registry
        manifest = {
            "name": "rf_synthetic_test",
            "classifier_type": "random_forest",
            "data_source": "synthetic",
            "active": True,
            "feature_columns": FEATURE_COLUMNS,
            "feature_schema_version": "1.0.0",
        }
        (reg_dir / "registry_manifest.json").write_text(json.dumps([manifest]))

        cfg = AdaptShieldConfig()
        cfg.classifier.mode = "auto"
        cfg.classifier.registry_dir = str(reg_dir)
        cfg.classifier.allow_synthetic = False
        cfg.mode = "protect"

        # Mock registry.get_active_model to return dummy model + manifest
        with patch.object(ModelRegistry, "get_active_model", return_value=(MagicMock(), manifest)):
            clf, meta = select_classifier(cfg)
            # Must fall back to rule-based because synthetic model is guarded
            assert isinstance(clf, RuleBasedClassifier)
            assert meta["synthetic_blocked"] is True

            # If allow_synthetic is True, synthetic model should be permitted
            cfg.classifier.allow_synthetic = True
            clf2, meta2 = select_classifier(cfg)
            assert meta2["synthetic_blocked"] is False

            # In monitor mode, synthetic model is allowed even with allow_synthetic=False
            cfg.classifier.allow_synthetic = False
            cfg.mode = "monitor"
            clf3, meta3 = select_classifier(cfg)
            assert meta3["synthetic_blocked"] is False


def test_mode_manager_and_monitor_first_period():
    cfg = AdaptShieldConfig()
    cfg.mode = "protect"
    cfg.monitor_first_period_hours = 24

    # 1. Start fresh -> within 24h grace period -> active mode is monitor
    now = time.time()
    mgr = ModeManager(cfg, started_at=now)
    assert mgr.is_monitor_first_active() is True
    assert mgr.get_active_mode() == "monitor"

    # 2. Simulate 25 hours elapsed -> grace period expired -> active mode is protect
    mgr.started_at = now - (25 * 3600)
    assert mgr.is_monitor_first_active() is False
    assert mgr.get_active_mode() == "protect"

    # 3. If monitor_first_period_hours == 0 -> starts in protect immediately
    cfg.monitor_first_period_hours = 0
    mgr_zero = ModeManager(cfg, started_at=now)
    assert mgr_zero.is_monitor_first_active() is False
    assert mgr_zero.get_active_mode() == "protect"

    # 4. Manual override switches mode immediately
    mgr_zero.set_mode("learn")
    assert mgr_zero.get_active_mode() == "learn"


def test_telemetry_writer_rotation():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1 MB rotation cap for quick testing
        writer = TelemetryWriter(telemetry_dir=tmp_dir, rotation_mb=1, enabled=True)
        assert writer.enabled is True

        dummy_features = {col: 1.0 for col in FEATURE_COLUMNS}
        writer.record(
            pid=1234,
            mode="protect",
            risk_score=0.92,
            risk_level="CRITICAL",
            action="contained",
            features=dummy_features,
            comm="bad_encryptor",
            explanation={"type": "rule_based"},
        )
        writer.flush()

        files = list(Path(tmp_dir).glob("telemetry_*.jsonl"))
        assert len(files) >= 1
        content = files[0].read_text()
        assert "bad_encryptor" in content
        assert "CRITICAL" in content

        writer.close()


def test_alert_explanation_generation():
    # Rule based explanation
    rule_clf = RuleBasedClassifier()
    row_rule = {"mod_rate": 85.0, "rename_rate": 35.0}
    expl_rule = explain_alert(rule_clf, row_rule, "rule_based")
    assert expl_rule["type"] == "rule_based"
    assert len(expl_rule["fired_rules"]) == 2

    # Tree based explanation
    dummy_tree_clf = MagicMock()
    dummy_tree_clf.columns = FEATURE_COLUMNS
    dummy_tree_clf.model.feature_importances_ = [0.1] * len(FEATURE_COLUMNS)
    row_tree = {"t1_mean_entropy": 7.8, "mod_rate": 90.0, "rename_rate": 40.0}
    expl_tree = explain_alert(dummy_tree_clf, row_tree, "xgboost")
    assert expl_tree["type"] == "tree_importance"
    assert len(expl_tree["contributions"]) > 0


def test_daemon_stop_and_hot_reload():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = AdaptShieldConfig()
        cfg.response.control_dir = str(Path(tmp_dir) / "control")
        cfg.response.quarantine_dir = str(Path(tmp_dir) / "quarantine")
        cfg.logging.alert_file = str(Path(tmp_dir) / "alert.jsonl")
        cfg.telemetry.enabled = True
        cfg.telemetry.dir = str(Path(tmp_dir) / "telemetry")

        daemon = AdaptShieldDaemon.from_config(cfg, dry_run=True)
        assert daemon.mode_mgr.get_active_mode() in ("monitor", "protect")

        # Test hot reload with updated config
        new_cfg = AdaptShieldConfig()
        new_cfg.mode = "learn"
        new_cfg.monitor_first_period_hours = 0
        new_cfg.detection.theta0 = 0.8
        daemon.reload_config(new_cfg)

        assert daemon.config.mode == "learn"
        assert daemon.mode_mgr.get_active_mode() == "learn"
        assert daemon.config.detection.theta0 == 0.8

        # Test graceful stop
        daemon.stop(thaw_processes=True)


def test_mock_agent_event_cycle():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = AdaptShieldConfig()
        cfg.response.control_dir = str(Path(tmp_dir) / "control")
        cfg.response.quarantine_dir = str(Path(tmp_dir) / "quarantine")
        alert_file = Path(tmp_dir) / "alert.jsonl"
        cfg.logging.alert_file = str(alert_file)
        cfg.mode = "monitor"
        cfg.monitor_first_period_hours = 0
        cfg.classifier.mode = "rule_based"
        cfg.detection.use_risk_smoothing = False
        cfg.detection.consecutive_windows_for_critical = 1

        daemon = AdaptShieldDaemon.from_config(cfg, dry_run=True)

        # High risk row for test pid with canonical 11 features
        row_critical = {
            "pid": 8888,
            "mod_rate": 100.0,
            "rename_rate": 50.0,
            "create_del_rate": 20.0,
            "event_count": 200.0,
            "concentration_gini": 0.85,
            "t1_write_rate": 80.0,
            "t1_mean_entropy": 7.9,
            "t1_entropy_std": 0.1,
            "t1_unlink_rate": 10.0,
            "t1_rename_rate": 40.0,
            "t1_mean_write_size": 4096.0,
        }

        # Run _classify_and_score in monitor mode
        daemon._classify_and_score([row_critical])

        # In monitor mode, PID should NOT be contained in response
        assert 8888 not in daemon._contained_pids

        # Switch to protect mode with dry-run
        daemon.config.mode = "protect"
        daemon.mode_mgr.set_mode("protect")
        daemon._classify_and_score([row_critical])

        # In protect mode with dry-run, PID is marked in _contained_pids
        assert 8888 in daemon._contained_pids

        daemon.stop()

