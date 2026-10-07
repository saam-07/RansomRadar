"""
Unit tests for the unified `adaptshield` command line interface.
Verifies argument parsing, output formats, and subcommand dispatching.
"""
import io
import json
import sys
import tempfile
from pathlib import Path

import yaml

from adaptshield.cli import main as cli_main
from adaptshield.config import AdaptShieldConfig
from adaptshield.state import StateManager


def run_cli_args(*args):
    """Helper to run cli_main with given arguments and capture stdout."""
    old_stdout = sys.stdout
    old_argv = sys.argv
    captured = io.StringIO()
    try:
        sys.stdout = captured
        sys.argv = ["adaptshield"] + list(args)
        cli_main()
    finally:
        sys.stdout = old_stdout
        sys.argv = old_argv
    return captured.getvalue()


def test_cli_version():
    out = run_cli_args("version")
    assert "AdaptShield version 0.2.0" in out


def test_cli_status():
    out = run_cli_args("status")
    assert "AdaptShield Endpoint Agent Status" in out
    assert "Operating Mode:" in out
    assert "Response Policy:" in out
    assert "Configured Detector:" in out
    assert "Effective Containment Detector:" in out
    assert "Active Detector:" in out


def test_cli_doctor():
    out = run_cli_args("doctor")
    assert "AdaptShield Preflight Health & Diagnostics" in out
    assert "OS Platform:" in out
    assert "Privileges:" in out
    assert "Doctor diagnostics completed." in out


def test_cli_mode():
    with tempfile.TemporaryDirectory() as tmp_dir:
        conf_file = Path(tmp_dir) / "config.yaml"
        conf_file.write_text(yaml.safe_dump({"mode": "protect"}))

        # Show mode
        out = run_cli_args("-c", str(conf_file), "mode")
        assert "protect" in out

        # Change mode
        out_set = run_cli_args("-c", str(conf_file), "mode", "monitor")
        assert "mode set to 'monitor'" in out_set
        data = yaml.safe_load(conf_file.read_text())
        assert data["mode"] == "monitor"


def test_cli_config_check_and_show():
    with tempfile.TemporaryDirectory() as tmp_dir:
        conf_file = Path(tmp_dir) / "config.yaml"
        conf_file.write_text(yaml.safe_dump(AdaptShieldConfig().model_dump()))

        out_check = run_cli_args("-c", str(conf_file), "config", "check")
        assert "Configuration is valid" in out_check

        out_show = run_cli_args("-c", str(conf_file), "config", "show")
        assert "mode:" in out_show


def test_cli_allowlist_management():
    with tempfile.TemporaryDirectory() as tmp_dir:
        conf_file = Path(tmp_dir) / "config.yaml"
        conf_file.write_text(yaml.safe_dump({"allowlist": {"process_names": ["systemd", "rsync"]}}))

        # List
        out_list = run_cli_args("-c", str(conf_file), "allowlist", "list")
        assert "systemd" in out_list

        # Add
        out_add = run_cli_args("-c", str(conf_file), "allowlist", "add", "my_backup_daemon")
        assert "Added 'my_backup_daemon'" in out_add

        # Remove
        out_rem = run_cli_args("-c", str(conf_file), "allowlist", "remove", "my_backup_daemon")
        assert "Removed 'my_backup_daemon'" in out_rem


def test_cli_containment_list_show_release():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "state.json"
        ctrl_dir = Path(tmp_dir) / "control"
        ctrl_dir.mkdir(parents=True, exist_ok=True)

        mgr = StateManager(state_file)
        mgr.record_containment(pid=9999, policy="manual", status="awaiting_manual", evidence={"score": 0.95})

        conf_file = Path(tmp_dir) / "config.yaml"
        conf_file.write_text(yaml.safe_dump({
            "response": {"control_dir": str(ctrl_dir), "quarantine_dir": str(tmp_dir)}
        }))

        # List
        out_list = run_cli_args("-c", str(conf_file), "list")
        assert "9999" in out_list

        # Show
        out_show = run_cli_args("-c", str(conf_file), "show", "9999")
        assert "awaiting_manual" in out_show

        # Release
        out_rel = run_cli_args("-c", str(conf_file), "release", "9999")
        assert "Successfully released and thawed PID 9999" in out_rel


def test_cli_alerts_output():
    with tempfile.TemporaryDirectory() as tmp_dir:
        alert_file = Path(tmp_dir) / "alert.jsonl"
        alert_record = {
            "timestamp": 1700000000.0,
            "event": "alert_critical",
            "pid": 5555,
            "risk_ewma": 0.88,
            "explanation": {"summary": "Rapid modification rate"},
        }
        alert_file.write_text(json.dumps(alert_record) + "\n")

        conf_file = Path(tmp_dir) / "config.yaml"
        conf_file.write_text(yaml.safe_dump({"logging": {"alert_file": str(alert_file)}}))

        out_json = run_cli_args("-c", str(conf_file), "alerts", "--json")
        assert "5555" in out_json
        assert "Rapid modification rate" in out_json


def test_cli_simulate_benign():
    with tempfile.TemporaryDirectory() as tmp_dir:
        out = run_cli_args("simulate", "benign", "--target", tmp_dir)
        assert "Benign simulation finished" in out


def test_cli_release_all():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "state.json"
        ctrl_dir = Path(tmp_dir) / "control"
        ctrl_dir.mkdir(parents=True, exist_ok=True)

        mgr = StateManager(state_file)
        mgr.record_containment(pid=1111, policy="manual", status="awaiting_manual", evidence={})
        mgr.record_containment(pid=2222, policy="manual", status="awaiting_manual", evidence={})

        conf_file = Path(tmp_dir) / "config.yaml"
        conf_file.write_text(yaml.safe_dump({
            "response": {"control_dir": str(ctrl_dir), "quarantine_dir": str(tmp_dir)}
        }))

        out = run_cli_args("-c", str(conf_file), "release", "--all")
        assert "Released and thawed PID 1111" in out
        assert "Released and thawed PID 2222" in out

        # Now list should be empty
        out_list = run_cli_args("-c", str(conf_file), "list")
        assert "No contained or pending processes found." in out_list


def test_cli_status_handles_permission_error_gracefully(monkeypatch):
    """Verifies that adaptshield status does NOT crash with a traceback on PermissionError."""
    from adaptshield.response.protection import ProtectionManager

    def mock_load_manifest(self):
        self.manifest_permission_denied = True
        raise PermissionError("Permission denied: /var/lib/adaptshield/protection_manifest.json")

    monkeypatch.setattr(ProtectionManager, "load_manifest", mock_load_manifest)

    out = run_cli_args("status")
    assert "AdaptShield Endpoint Agent Status" in out
    assert "WARNING: Protection manifest or system state is not readable" in out
    assert "sudo usermod -aG adaptshield" in out
    assert "Traceback" not in out


def test_cli_log_path_resolution(monkeypatch, tmp_path):
    """Verify that installed log file /var/log/adaptshield is prioritized if accessible."""
    from adaptshield.cli import get_effective_alert_file, get_effective_log_file
    from adaptshield.config import AdaptShieldConfig

    cfg = AdaptShieldConfig()
    cfg.logging.file = "relative.log"
    cfg.logging.alert_file = "alerts.jsonl"

    var_log_dir = tmp_path / "var_log"
    var_log_dir.mkdir()
    var_log_file = var_log_dir / "adaptshield.log"
    var_alert_file = var_log_dir / "alerts.jsonl"
    var_log_file.write_text("dummy log")
    var_alert_file.write_text("dummy alert\n")

    monkeypatch.setattr("adaptshield.cli.SYSTEM_LOG_FILE", var_log_file)
    monkeypatch.setattr("adaptshield.cli.SYSTEM_ALERT_FILE", var_alert_file)

    eff_log = get_effective_log_file(cfg)
    assert eff_log == str(var_log_file)

    eff_alert = get_effective_alert_file(cfg)
    assert eff_alert == str(var_alert_file)


def test_cli_alerts_handles_permission_error_gracefully(monkeypatch, tmp_path):
    """Verifies that adaptshield alerts does NOT crash with traceback on PermissionError."""
    fake_alert = tmp_path / "fake_alert.jsonl"
    fake_alert.write_text('{"event": "TEST"}\n')

    def mock_open(*args, **kwargs):
        raise PermissionError("Permission denied reading alerts")

    monkeypatch.setattr("adaptshield.cli.SYSTEM_ALERT_FILE", fake_alert)
    monkeypatch.setattr("builtins.open", mock_open)
    out = run_cli_args("alerts")
    assert "WARNING: Alert log at" in out
    assert "sudo usermod -aG adaptshield" in out
    assert "Traceback" not in out


def test_cli_doctor_containment_and_detector_output():
    """Verify doctor outputs Containment Backend and Active Detector."""
    out = run_cli_args("doctor")
    assert "Containment Backend:" in out
    assert "Active Detector:" in out
    assert "Privileges:" in out


def test_cli_logging_read_only_avoids_service_log_write():
    """Verify that default CLI logging does not attach a write FileHandler against the service log."""
    import logging
    from adaptshield.logging.logger import setup_logging

    root_logger = setup_logging()
    file_handlers = [h for h in root_logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 0, "CLI logging must remain read-only without attaching write FileHandlers"


def test_cli_status_displays_effective_containment_detector_with_synthetic_guard():
    """Verify status reports Configured Detector and Effective Containment Detector with synthetic guard."""
    out = run_cli_args("status")
    assert "Configured Detector:" in out
    assert "Effective Containment Detector:" in out
    if "xgboost" in out and "Synthetic Guard: ACTIVE" in out:
        assert "rule_based" in out


