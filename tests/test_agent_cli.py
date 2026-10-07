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
