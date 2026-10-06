import time
import pytest

from backend.app.core.bus import EventBus
from backend.app.core.pipeline import DetectionPipeline
from backend.app.core.response import SimulatedResponse
from backend.app.core.safety import SafetyRails
from backend.app.core.sources import SimulatedSource


def test_scenario_runs_are_deterministic_with_seed():
    """Identical seed must yield identical summary metrics and event sequences."""
    pipeline1 = DetectionPipeline(model_name="xgboost")
    pipeline2 = DetectionPipeline(model_name="xgboost")

    res1 = pipeline1.run_scenario("fast_ransomware", seed=42)
    res2 = pipeline2.run_scenario("fast_ransomware", seed=42)

    assert res1["total_windows"] == res2["total_windows"]
    assert res1["contained_pids"] == res2["contained_pids"]
    assert res1["time_to_detect_windows"] == res2["time_to_detect_windows"]
    assert res1["filesystem_status"] == res2["filesystem_status"]


def test_benign_and_backup_produce_zero_containments():
    """'normal_workday' and 'nightly_backup' must produce zero containments with xgboost."""
    pipeline_workday = DetectionPipeline(model_name="xgboost")
    res_workday = pipeline_workday.run_scenario("normal_workday", seed=42)
    assert res_workday["contained_pids"] == []
    assert res_workday["time_to_detect_windows"] is None

    pipeline_backup = DetectionPipeline(model_name="xgboost")
    res_backup = pipeline_backup.run_scenario("nightly_backup", seed=42)
    assert res_backup["contained_pids"] == []
    assert res_backup["time_to_detect_windows"] is None


def test_fast_ransomware_contained_and_rolled_back():
    """'fast_ransomware' must be detected, contained, and all encrypted files restored."""
    resp_engine = SimulatedResponse(num_virtual_files=60, default_policy="immediate")
    pipeline = DetectionPipeline(model_name="xgboost", response_engine=resp_engine)

    res = pipeline.run_scenario("fast_ransomware", seed=42)
    assert len(res["contained_pids"]) == 1
    assert res["time_to_detect_windows"] is not None

    # Verify virtual filesystem rollback: all encrypted files restored
    fs_summary = resp_engine.get_filesystem_summary()
    assert fs_summary["status_counts"]["encrypted"] == 0
    assert fs_summary["status_counts"]["restored"] > 0


def test_independent_per_process_containment():
    """Containing two simultaneous attackers must be independent: releasing one does not thaw the other."""
    resp = SimulatedResponse(num_virtual_files=60, default_policy="manual")
    pid_a, pid_b = 9001, 9002

    # Freeze both attackers under manual policy
    resp.freeze(pid_a)
    resp.freeze(pid_b)

    st_a = resp.get_process_state(pid_a)
    st_b = resp.get_process_state(pid_b)
    assert st_a["is_frozen"] is True
    assert st_b["is_frozen"] is True

    # Release PID A (false positive release)
    resp.unfreeze(pid_a)

    st_a_after = resp.get_process_state(pid_a)
    st_b_after = resp.get_process_state(pid_b)
    assert st_a_after["is_frozen"] is False
    assert st_a_after["decision_state"] == "resolved_released"

    # PID B must REMAIN frozen!
    assert st_b_after["is_frozen"] is True
    assert st_b_after["decision_state"] == "pending_manual_decision"


def test_manual_policy_release_confirm_timeout():
    """Tests manual decision release, confirmation, and automatic timeout resolution."""
    resp = SimulatedResponse(num_virtual_files=60, default_policy="manual")
    pid_manual = 9100

    resp.freeze(pid_manual)
    st = resp.get_process_state(pid_manual)
    assert st["decision_state"] == "pending_manual_decision"

    # Test auto-resolve timeout (simulate clock advancing past 10 seconds)
    st_obj = resp.processes[pid_manual]
    st_obj.auto_resolve_after_seconds = 5.0
    st_obj.auto_resolve_action = "confirm"

    # Advance time by 6 seconds
    past_time = st_obj.frozen_at + 6.0
    actions = resp.check_auto_resolve(now=past_time)
    assert len(actions) == 1
    assert actions[0]["action"] == "auto_confirm"

    st_resolved = resp.get_process_state(pid_manual)
    assert st_resolved["decision_state"] == "resolved_confirmed"
    assert st_resolved["is_rolled_back"] is True
    assert st_resolved["is_killed"] is True


def test_allowlisted_process_is_never_contained():
    """Allowlisted processes are never contained even if risk evaluates high."""
    safety = SafetyRails()
    safety.add_allowlist("critical_service")

    # Check can contain
    allowed, reason = safety.check_can_contain(pid=9999, process_name="critical_service")
    assert allowed is False
    assert "Allowlisted" in reason

    # System daemons and PID 1
    allowed_pid1, _ = safety.check_can_contain(pid=1, process_name="systemd")
    assert allowed_pid1 is False


def test_event_bus_publishes_all_pipeline_events():
    """EventBus captures window_scored, alert, and containment events."""
    bus = EventBus()
    received_events = []
    bus.subscribe("*", lambda evt: received_events.append(evt["type"]))

    pipeline = DetectionPipeline(model_name="xgboost", event_bus=bus)
    pipeline.run_scenario("fast_ransomware", seed=42)

    assert "window_scored" in received_events
    assert "alert" in received_events
    assert "containment" in received_events
