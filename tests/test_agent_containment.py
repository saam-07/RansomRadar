"""
Unit tests for per-PID containment isolation, safety rails, self-exclusion,
state persistence, crash recovery, and dry-run execution.
"""
import os
import tempfile
import time
from pathlib import Path
import pytest

from adaptshield.config import AdaptShieldConfig
from adaptshield.response.containment_manager import (
    ContainmentManager,
    RollbackPolicy,
    contain,
    freeze_pid,
    unfreeze_pid,
    is_pid_frozen,
    list_frozen_pids,
    get_pid_cgroup,
)
from adaptshield.response.safety import SafetyRails
from adaptshield.state import StateManager, ContainedProcessRecord


def test_per_pid_cgroup_isolation_regression():
    """
    Problem 4 regression test: contain two PIDs independently;
    releasing one MUST NOT unfreeze the other.
    """
    with tempfile.TemporaryDirectory() as tmp_cgroup:
        cgroup_parent = Path(tmp_cgroup)

        pid_a = 7001
        pid_b = 7002

        # 1. Freeze both processes
        freeze_pid(pid_a, cgroup_parent=cgroup_parent)
        freeze_pid(pid_b, cgroup_parent=cgroup_parent)

        assert is_pid_frozen(pid_a, cgroup_parent=cgroup_parent) is True
        assert is_pid_frozen(pid_b, cgroup_parent=cgroup_parent) is True
        frozen_list = list_frozen_pids(cgroup_parent=cgroup_parent)
        assert pid_a in frozen_list
        assert pid_b in frozen_list

        # 2. Release ONLY PID A
        unfreeze_pid(pid_a, cgroup_parent=cgroup_parent)

        # 3. Assert PID A is thawed while PID B STAYS FROZEN
        assert is_pid_frozen(pid_a, cgroup_parent=cgroup_parent) is False
        assert is_pid_frozen(pid_b, cgroup_parent=cgroup_parent) is True, "PID B must remain frozen after PID A is released"

        # 4. Release PID B
        unfreeze_pid(pid_b, cgroup_parent=cgroup_parent)
        assert is_pid_frozen(pid_b, cgroup_parent=cgroup_parent) is False


def test_safety_rails_process_immunity():
    cfg = AdaptShieldConfig()
    safety = SafetyRails(cfg)

    # 1. PID 1 Protection
    immune, reason = safety.is_immune(1)
    assert immune is True
    assert "PID 1" in reason

    # 2. Agent Daemon Self and Parent
    immune, reason = safety.is_immune(os.getpid())
    assert immune is True
    assert "self" in reason

    # 3. Critical System Daemons
    immune, reason = safety.is_immune(999, process_name="systemd-journald")
    assert immune is True

    immune, reason = safety.is_immune(888, process_name="sshd")
    assert immune is True

    # 4. Config Allowlist Process Names (backup tools, DBs)
    immune, reason = safety.is_immune(1234, process_name="restic")
    assert immune is True
    assert "Allowlisted" in reason

    immune, reason = safety.is_immune(1235, process_name="tar")
    assert immune is True

    # 5. Allowlist Exe Paths
    immune, reason = safety.is_immune(5555, exe_path="/usr/lib/systemd/systemd-logind")
    assert immune is True

    # 6. Non-immune suspicious process
    immune, _ = safety.is_immune(4099, process_name="ransom_worker", exe_path="/tmp/malware")
    assert immune is False


def test_safety_rails_storm_panic_switch():
    cfg = AdaptShieldConfig()
    cfg.safety_rails.storm_threshold_distinct_pids = 4
    cfg.safety_rails.storm_window_seconds = 10
    safety = SafetyRails(cfg)

    # Containments for 3 distinct PIDs should be permitted
    p1, _ = safety.check_containment_permitted(101)
    p2, _ = safety.check_containment_permitted(102)
    p3, _ = safety.check_containment_permitted(103)
    assert p1 is True
    assert p2 is True
    assert p3 is True
    assert safety.panic_switch_tripped is False

    # 4th distinct PID trips the panic switch
    p4, reason = safety.check_containment_permitted(104)
    assert p4 is False
    assert safety.panic_switch_tripped is True
    assert "storm panic switch" in reason

    # Subsequent containments remain suppressed while in panic state
    p5, reason5 = safety.check_containment_permitted(105)
    assert p5 is False
    assert "MONITOR" in reason5


def test_self_exclusion_paths():
    cfg = AdaptShieldConfig()
    safety = SafetyRails(cfg)

    # Quarantine and state directories must be excluded
    assert safety.is_self_exclusion_path("/var/lib/adaptshield/quarantine/pid100_test") is True
    assert safety.is_self_exclusion_path("/var/lib/adaptshield/control/decision_pid100.json") is True
    # User document paths are not excluded
    assert safety.is_self_exclusion_path("/home/user/documents/report.docx") is False


def test_runtime_state_persistence_and_recovery():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "state.json"
        ctrl_dir = Path(tmp_dir) / "control"
        ctrl_dir.mkdir(parents=True, exist_ok=True)

        mgr = StateManager(state_file)
        evidence = {"mod_rate": 85.0}

        # 1. Record a contained PID under manual policy
        mgr.record_containment(
            pid=9999,
            policy="manual",
            status="awaiting_manual",
            evidence=evidence,
            overlay_upper=str(Path(tmp_dir) / "upper"),
            overlay_work=str(Path(tmp_dir) / "work"),
        )
        assert state_file.exists()

        # 2. Reload state in a fresh StateManager instance
        mgr_reloaded = StateManager(state_file)
        assert 9999 in mgr_reloaded.records
        rec = mgr_reloaded.records[9999]
        assert rec.policy == "manual"
        assert rec.status == "awaiting_manual"

        # 3. Test recovery with timeout not reached -> resumes manual decision
        cfg = AdaptShieldConfig()
        cfg.response.control_dir = str(ctrl_dir)
        cfg.response.auto_resolve_after_seconds = 1000.0  # far in future
        # Mock is_process_alive so test simulates an active frozen process
        mgr_reloaded.is_process_alive = lambda p: True

        summary = mgr_reloaded.recover(cfg)
        assert summary["recovered_count"] >= 1
        assert mgr_reloaded.records[9999].status == "awaiting_manual"

        # 4. Test recovery with timeout reached -> auto-resolves with release
        cfg.response.auto_resolve_after_seconds = 0.0001
        cfg.response.auto_resolve_action = "release"
        # Simulate time passage
        mgr_reloaded.records[9999].frozen_at = time.time() - 100.0

        summary2 = mgr_reloaded.recover(cfg)
        assert summary2["actions"].get(9999) == "auto_released"
        assert mgr_reloaded.records[9999].status == "auto_released"

        # 5. Test recovery of terminated process cleans up cgroup
        mgr_dead = StateManager(Path(tmp_dir) / "state_dead.json")
        mgr_dead.record_containment(pid=8888, policy="immediate", status="frozen", evidence={})
        mgr_dead.is_process_alive = lambda p: False
        dead_summary = mgr_dead.recover(cfg)
        assert dead_summary["actions"].get(8888) == "cleaned_up_dead"


def test_dry_run_containment_mode():
    with tempfile.TemporaryDirectory() as tmp_dir:
        upper = Path(tmp_dir) / "upper"
        work = Path(tmp_dir) / "work"
        quarantine = Path(tmp_dir) / "quarantine"
        upper.mkdir()
        work.mkdir()
        quarantine.mkdir()

        # Execute containment with dry_run=True
        result = contain(
            pid=8888,
            upperdir=str(upper),
            workdir=str(work),
            quarantine_root=str(quarantine),
            policy=RollbackPolicy.IMMEDIATE,
            dry_run=True,
        )

        assert result.dry_run is True
        assert result.killed is False
        assert result.rolled_back is False
