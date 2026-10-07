"""
Unit tests for AdaptShield configuration loading, validation, and defaults.
"""
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from adaptshield.config import (
    AdaptShieldConfig,
    DetectionConfig,
    ResponseConfig,
    load_config,
)


def test_default_config_instantiation():
    cfg = AdaptShieldConfig()
    assert cfg.mode == "protect"
    assert cfg.monitor_first_period_hours == 24
    assert "/home" in cfg.watch.paths
    assert "/proc" in cfg.watch.excludes
    assert cfg.response.policy == "immediate"
    assert cfg.response.use_freeze is True
    assert cfg.detection.theta0 == 0.5
    assert cfg.detection.use_tier1 is True
    assert cfg.classifier.mode == "auto"
    assert cfg.classifier.allow_synthetic is False
    assert len(cfg.allowlist.process_names) > 0


def test_config_policy_validation():
    # Valid policies
    for p in ["none", "immediate", "manual"]:
        cfg = ResponseConfig(policy=p)
        assert cfg.policy == p

    # Invalid policy
    with pytest.raises(ValidationError):
        ResponseConfig(policy="destroy_everything")


def test_config_mode_validation():
    for m in ["monitor", "protect", "learn"]:
        cfg = AdaptShieldConfig(mode=m)
        assert cfg.mode == m

    with pytest.raises(ValidationError):
        AdaptShieldConfig(mode="aggressive_destroy")


def test_config_load_from_yaml():
    yaml_content = """
mode: "monitor"
monitor_first_period_hours: 0
watch:
  paths:
    - "/test/mnt"
  excludes:
    - "/test/mnt/ignore"
response:
  policy: "manual"
  auto_resolve_after_seconds: 60.0
  auto_resolve_action: "release"
detection:
  theta0: 0.75
  ewma_alpha: 0.5
classifier:
  mode: "rule_based"
  model_name: "rule_based"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        tmp_path = f.name

    try:
        cfg = load_config(tmp_path)
        assert cfg.mode == "monitor"
        assert cfg.monitor_first_period_hours == 0
        assert cfg.watch.paths == ["/test/mnt"]
        assert cfg.response.policy == "manual"
        assert cfg.response.auto_resolve_after_seconds == 60.0
        assert cfg.detection.theta0 == 0.75
        assert cfg.detection.ewma_alpha == 0.5
        assert cfg.classifier.mode == "rule_based"
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_config_load_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/to/config.yaml")


def test_packaging_default_config_validates():
    default_cfg_path = Path("packaging/config.default.yaml")
    if default_cfg_path.exists():
        cfg = load_config(default_cfg_path)
        assert cfg.mode in {"monitor", "protect", "learn"}
        assert cfg.response.policy in {"none", "immediate", "manual"}


def test_config_threshold_validation():
    # Out of range theta0 (> 1.0)
    with pytest.raises(ValidationError):
        DetectionConfig(theta0=1.5)

    # Negative theta0
    with pytest.raises(ValidationError):
        DetectionConfig(theta0=-0.1)

    # Valid DetectionConfig
    cfg = DetectionConfig(theta0=0.65, ewma_alpha=0.4)
    assert cfg.theta0 == 0.65
    assert cfg.ewma_alpha == 0.4

