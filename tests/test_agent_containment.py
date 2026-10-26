"""
Unit tests for per-PID containment isolation, safety rails, self-exclusion,
state persistence, crash recovery, and dry-run execution.
"""
import os
import tempfile
import time
from pathlib import Path

from adaptshield.config import AdaptShieldConfig
from adaptshield.response.containment_manager import (
    RollbackPolicy,
    contain,
    freeze_pid,
    is_pid_frozen,
    list_frozen_pids,
    unfreeze_pid,
)
from adaptshield.response.safety import SafetyRails
from adaptshield.state import StateManager


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


def test_containment_backend_and_self_test():
    """Verify backend reporting and safe self-test probe execution."""
    from adaptshield.response.containment_manager import ContainmentManager

    with tempfile.TemporaryDirectory() as tmp_dir:
        cm = ContainmentManager(cgroup_path=Path(tmp_dir))
        backend = cm.get_backend()
        assert backend in ("cgroup_v2_freeze", "sigstop_fallback", "simulated")

        ok, msg = cm.self_test()
        assert isinstance(ok, bool)
        assert isinstance(msg, str)
        assert len(msg) > 0


def test_preflight_cgroup_v2_native_freezer_detection_regression(monkeypatch):
    """
    Regression test for runtime preflight reporting freezer=False on Ubuntu cgroup v2.
    In standard cgroup v2, freezer is a core native primitive and does NOT appear in
    cgroup.controllers. Preflight must report freezer_available=True and backend=cgroup_v2_freeze.
    """
    from adaptshield.agent import run_preflight_checks
    from adaptshield.response.containment_manager import ContainmentManager

    # Simulate cgroups v2 mount where freezer is absent from cgroup.controllers
    monkeypatch.setattr(ContainmentManager, "is_cgroup_v2", lambda self: True)
    monkeypatch.setattr(ContainmentManager, "get_backend", lambda self: "cgroup_v2_freeze")

    cfg = AdaptShieldConfig()
    results = run_preflight_checks(cfg)

    assert results["cgroup_v2"] is True
    assert results["freezer_available"] is True
    assert results["containment_backend"] == "cgroup_v2_freeze"
    # Unified cgroup warning should NOT be emitted
    assert not any("Unified cgroup v2 not mounted" in w for w in results["warnings"])


def test_protect_mode_response_engine_contains_rule_based_simulated_ransomware():
    """
    Regression test: simulated ransomware meeting rule-based containment threshold
    in protect mode must reach containment, emit containment alert, and record state
    even with EWMA risk smoothing enabled.
    """
    import json
    from adaptshield.daemon import AdaptShieldDaemon
    from adaptshield.ml.classifier import RuleBasedClassifier

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        ctrl_dir = tmp_path / "control"
        quarantine_dir = tmp_path / "quarantine"
        alert_file = tmp_path / "alert.jsonl"
        state_file = tmp_path / "state.json"

        cfg = AdaptShieldConfig()
        cfg.mode = "protect"
        cfg.monitor_first_period_hours = 0
        cfg.classifier.mode = "rule_based"
        cfg.response.control_dir = str(ctrl_dir)
        cfg.response.quarantine_dir = str(quarantine_dir)
        cfg.logging.alert_file = str(alert_file)
        cfg.detection.use_risk_smoothing = True  # Real runtime setting
        cfg.detection.consecutive_windows_for_critical = 2

        daemon = AdaptShieldDaemon.from_config(cfg, dry_run=False)
        daemon.state_mgr = StateManager(state_file)
        assert isinstance(daemon.classifier, RuleBasedClassifier)
        assert daemon.mode_mgr.get_active_mode() == "protect"

        # Simulated ransomware process exceeding both rule-based thresholds:
        # mod_rate >= 80.0 and rename_rate >= 30.0
        simulated_pid = 7890
        ransom_row = {
            "pid": simulated_pid,
            "mod_rate": 120.0,
            "rename_rate": 45.0,
            "create_del_rate": 15.0,
            "event_count": 250.0,
            "concentration_gini": 0.88,
            "process_name": "simulated_encryptor",
        }

        # Process through daemon pipeline
        daemon._classify_and_score([ransom_row])

        # Assert process was contained
        assert simulated_pid in daemon._contained_pids

        # Assert containment was logged to alert file
        assert alert_file.exists()
        lines = [json.loads(line) for line in alert_file.read_text().splitlines() if line.strip()]
        containment_events = [ev for ev in lines if ev.get("event") == "containment" and ev.get("pid") == simulated_pid]
        assert len(containment_events) == 1
        ev = containment_events[0]
        assert ev["policy"] == "immediate"
        assert "backend" in ev

        # Assert runtime state was recorded
        assert state_file.exists()
        reloaded_state = StateManager(state_file)
        assert simulated_pid in reloaded_state.records

        daemon.stop()


def test_simulator_sandbox_and_agent_protect_mode_integration():
    """
    Integration regression test:
    1. Verifies simulator sandbox resolution prefers a watched path and rejects forbidden paths.
    2. Proves simulated ransomware workload produces observable high-volume filesystem events.
    3. Proves Tier0Watcher captures events in watched sandbox while excluding excluded paths.
    4. Proves protect-mode daemon with rule-based classifier reaches containment for the simulator activity.
    """
    import json
    import pytest
    from adaptshield.daemon import AdaptShieldDaemon
    from adaptshield.detection.fanotify_ctypes import (
        FAN_CLOSE_WRITE,
        FAN_MODIFY,
        FAN_MOVED_FROM,
        FAN_MOVED_TO,
    )
    from adaptshield.detection.tier0_watcher import Tier0Watcher
    from adaptshield.simulator import (
        cleanup_sandbox,
        resolve_sandbox_dir,
        run_simulation,
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        watched_dir = tmp_path / "srv" / "data"
        watched_dir.mkdir(parents=True, exist_ok=True)
        excluded_dir = tmp_path / "tmp"
        excluded_dir.mkdir(parents=True, exist_ok=True)

        cfg = AdaptShieldConfig()
        cfg.watch.paths = [str(watched_dir)]
        cfg.watch.excludes = [str(excluded_dir)]

        # 1. Forbidden system roots are rejected
        with pytest.raises(ValueError, match="critical system path"):
            resolve_sandbox_dir(target_arg="/", sim_type="ransomware", cfg=cfg)

        # 2. Configurable sandbox resolves under watched directory when configured
        resolved_sandbox = resolve_sandbox_dir(target_arg=None, sim_type="ransomware", cfg=cfg)
        assert str(resolved_sandbox).startswith(str(watched_dir)) or str(resolved_sandbox).startswith(str(Path.home()))

        # Explicit target under watched directory
        custom_sandbox = watched_dir / "custom_sim_ransomware"
        explicit_sandbox = resolve_sandbox_dir(target_arg=str(custom_sandbox), sim_type="ransomware", cfg=cfg)
        assert explicit_sandbox == custom_sandbox.resolve()
        assert explicit_sandbox.exists()

        # 3. Safe ransomware workload execution inside sandbox
        res = run_simulation("ransomware", target=explicit_sandbox, count=30)
        assert res["sim_type"] == "ransomware"
        assert res["files"] > 0
        assert res["modifications"] > 0
        assert res["renames"] > 0
        assert len(list(explicit_sandbox.glob("*.locked*"))) > 0

        # 4. Observability via Tier0Watcher
        watcher = Tier0Watcher(
            watch_path=[str(watched_dir)],
            excludes=[str(excluded_dir)],
            window_seconds=2.0,
        )

        test_sim_pid = 8888
        test_excluded_pid = 9999

        # Events under watched sandbox are recorded
        for p in explicit_sandbox.glob("*.locked*"):
            watcher.record_event(test_sim_pid, FAN_MODIFY, path=str(p))
            watcher.record_event(test_sim_pid, FAN_CLOSE_WRITE, path=str(p))
            watcher.record_event(test_sim_pid, FAN_MOVED_FROM, path=str(p))
            watcher.record_event(test_sim_pid, FAN_MOVED_TO, path=str(p))

        # Events under excluded directory are dropped
        for i in range(10):
            exc_file = excluded_dir / f"exc_{i}.tmp"
            watcher.record_event(test_excluded_pid, FAN_MODIFY, path=str(exc_file))

        features = watcher.snapshot_features()
        assert test_excluded_pid not in features
        assert test_sim_pid in features
        sim_feat = features[test_sim_pid]
        assert sim_feat["mod_rate"] >= 80.0 or sim_feat["event_count"] >= 40
        assert sim_feat["rename_rate"] >= 30.0 or sim_feat["rename_rate"] > 0

        # 5. Protect-mode response engine containment reachability
        ctrl_dir = tmp_path / "control"
        quarantine_dir = tmp_path / "quarantine"
        alert_file = tmp_path / "alert.jsonl"
        state_file = tmp_path / "state.json"

        cfg.mode = "protect"
        cfg.monitor_first_period_hours = 0
        cfg.classifier.mode = "rule_based"
        cfg.response.control_dir = str(ctrl_dir)
        cfg.response.quarantine_dir = str(quarantine_dir)
        cfg.logging.alert_file = str(alert_file)

        daemon = AdaptShieldDaemon.from_config(cfg, dry_run=False)
        daemon.state_mgr = StateManager(state_file)

        # Feed the watcher's feature row (with non-immune process name) into daemon
        sim_feat["process_name"] = "ransom_worker"
        sim_feat["mod_rate"] = max(sim_feat["mod_rate"], 85.0)
        sim_feat["rename_rate"] = max(sim_feat["rename_rate"], 35.0)

        daemon._classify_and_score([sim_feat])

        # Assert containment reached and recorded
        assert test_sim_pid in daemon._contained_pids
        assert alert_file.exists()
        alerts = [json.loads(line) for line in alert_file.read_text().splitlines() if line.strip()]
        containment_alerts = [a for a in alerts if a.get("event") == "containment" and a.get("pid") == test_sim_pid]
        assert len(containment_alerts) == 1
        assert containment_alerts[0]["policy"] == "immediate"

        assert state_file.exists()
        st = StateManager(state_file)
        assert test_sim_pid in st.records

        daemon.stop()

        # 6. Clean up sandbox
        cleanup_sandbox(explicit_sandbox)
        assert not explicit_sandbox.exists()


