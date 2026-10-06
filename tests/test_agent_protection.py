"""
Unit tests for AdaptShield overlay protection manager and multi-path watching.
All tests use temporary directories and mocked loopback/mount functions;
never touches real user filesystems or root mounts.
"""
import json
import os
import tempfile
from pathlib import Path

from adaptshield.config import AdaptShieldConfig
from adaptshield.detection.fanotify_ctypes import is_path_excluded
from adaptshield.detection.tier0_watcher import Tier0Watcher
from adaptshield.response.containment_manager import RollbackPolicy, contain
from adaptshield.response.protection import (
    ProtectionManager,
)


def test_is_path_excluded_behavior():
    excludes = ["/proc", "/sys", "/dev", "/var/lib/adaptshield", "/tmp"]

    assert is_path_excluded("/proc/1/cmdline", excludes) is True
    assert is_path_excluded("/var/lib/adaptshield/state.json", excludes) is True
    assert is_path_excluded("/tmp/test.txt", excludes) is True
    assert is_path_excluded("/tmp", excludes) is True

    assert is_path_excluded("/home/alice/document.docx", excludes) is False
    assert is_path_excluded("/srv/data/file.csv", excludes) is False
    assert is_path_excluded("/var/log/syslog", excludes) is False


def test_tier0_watcher_multi_path_and_self_exclusion():
    with tempfile.TemporaryDirectory() as tmp_dir:
        p1 = Path(tmp_dir) / "dir1"
        p2 = Path(tmp_dir) / "dir2"
        p1.mkdir()
        p2.mkdir()

        # Instantiate with multiple watch paths
        watcher = Tier0Watcher(
            watch_path=[str(p1), str(p2)],
            window_seconds=1.0,
            excludes=[str(p1 / "excluded")],
            excluded_pids={1001, 1002},
        )

        assert str(p1) in watcher.watch_paths
        assert str(p2) in watcher.watch_paths
        # Current process PID must be auto-included in self-exclusion
        assert os.getpid() in watcher.excluded_pids
        assert 1001 in watcher.excluded_pids


def test_protection_manager_setup_and_manifest_persistence():
    with tempfile.TemporaryDirectory() as tmp_dir:
        overlay_root = Path(tmp_dir) / "overlay"
        quarantine_dir = Path(tmp_dir) / "quarantine"
        state_file = Path(tmp_dir) / "manifest.json"
        protect_target = Path(tmp_dir) / "user_home"
        protect_target.mkdir()

        cfg = AdaptShieldConfig()
        cfg.protect_paths = [str(protect_target)]

        mounted_calls = []

        def mock_mount(lower, upper, work, merged):
            mounted_calls.append((lower, upper, work, merged))

        mgr = ProtectionManager(
            config=cfg,
            overlay_root=overlay_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
            mount_fn=mock_mount,
        )

        targets = mgr.setup_all()
        target = targets[str(protect_target)]

        assert target.status == "protected"
        assert target.rollback_available is True
        assert target.is_mounted is True
        assert len(mounted_calls) == 1
        assert Path(target.upperdir).exists()
        assert Path(target.workdir).exists()

        # Verify manifest saved
        assert state_file.exists()
        saved = json.loads(state_file.read_text())
        assert str(protect_target) in saved["targets"]
        assert saved["targets"][str(protect_target)]["status"] == "protected"


def test_protection_manager_fallback_when_mount_fails():
    with tempfile.TemporaryDirectory() as tmp_dir:
        overlay_root = Path(tmp_dir) / "overlay"
        quarantine_dir = Path(tmp_dir) / "quarantine"
        state_file = Path(tmp_dir) / "manifest.json"
        protect_target = Path(tmp_dir) / "srv_data"
        protect_target.mkdir()

        cfg = AdaptShieldConfig()
        cfg.protect_paths = [str(protect_target)]

        def failing_mount(lower, upper, work, merged):
            raise OSError("Mounting overlayfs not permitted (Operation not permitted)")

        mgr = ProtectionManager(
            config=cfg,
            overlay_root=overlay_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
            mount_fn=failing_mount,
        )

        targets = mgr.setup_all()
        target = targets[str(protect_target)]

        # Must cleanly degrade to fallback mode
        assert target.status == "fallback_quarantine_only"
        assert target.rollback_available is False
        assert target.is_mounted is False
        assert "Mounting overlayfs not permitted" in (target.reason or "")

        status = mgr.get_status()
        assert status["total_targets"] == 1
        assert status["protected_count"] == 0
        assert status["fallback_count"] == 1
        assert status["rollback_globally_available"] is False


def test_protection_manager_quarantine_and_rollback_flow():
    with tempfile.TemporaryDirectory() as tmp_dir:
        overlay_root = Path(tmp_dir) / "overlay"
        quarantine_dir = Path(tmp_dir) / "quarantine"
        state_file = Path(tmp_dir) / "manifest.json"
        protect_target = Path(tmp_dir) / "docs"
        protect_target.mkdir()

        cfg = AdaptShieldConfig()
        cfg.protect_paths = [str(protect_target)]

        mgr = ProtectionManager(
            config=cfg,
            overlay_root=overlay_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
            mount_fn=lambda lower, upper, work, merged: None,
        )
        mgr.setup_all()
        target = mgr.targets[str(protect_target)]

        # Simulate ransomware creating encrypted files in upperdir
        upper = Path(target.upperdir)
        enc_file = upper / "report.pdf.locked"
        enc_file.write_text("ENCRYPTED DATA")

        # 1. Rollback when overlay is available
        rolled_back, q_dir, files, b = mgr.quarantine_and_rollback(pid=1234, target_path=str(protect_target))
        assert rolled_back is True
        assert files == 1
        assert b > 0
        assert Path(q_dir).exists()
        # Upperdir must be cleared
        assert not enc_file.exists()

        # 2. Rollback when path is in fallback mode
        target.rollback_available = False
        target.status = "fallback_quarantine_only"
        rolled_back2, q_dir2, files2, b2 = mgr.quarantine_and_rollback(pid=5678, target_path=str(protect_target))
        assert rolled_back2 is False
        assert Path(q_dir2).exists()


def test_containment_manager_integration_with_rollback_unavailable():
    with tempfile.TemporaryDirectory() as tmp_dir:
        upper = Path(tmp_dir) / "upper"
        work = Path(tmp_dir) / "work"
        quarantine = Path(tmp_dir) / "quarantine"
        upper.mkdir()
        work.mkdir()
        quarantine.mkdir()

        # When rollback is unavailable (e.g. fallback filesystem)
        result = contain(
            pid=7777,
            upperdir=str(upper),
            workdir=str(work),
            quarantine_root=str(quarantine),
            policy=RollbackPolicy.IMMEDIATE,
            use_freeze=True,
            rollback_available=False,
            rollback_reason="Overlayfs not supported on this volume",
        )

        assert result.rollback_available is False
        assert result.rolled_back is False
        assert result.killed is True
        assert result.quarantine_path is not None
        assert "Overlayfs not supported" in (result.rollback_reason or "")


def test_protection_manager_remount_after_reboot():
    with tempfile.TemporaryDirectory() as tmp_dir:
        overlay_root = Path(tmp_dir) / "overlay"
        quarantine_dir = Path(tmp_dir) / "quarantine"
        state_file = Path(tmp_dir) / "manifest.json"
        protect_target = Path(tmp_dir) / "docs"
        protect_target.mkdir()

        cfg = AdaptShieldConfig()
        cfg.protect_paths = [str(protect_target)]

        mount_history = []

        def tracking_mount(lower, upper, work, merged):
            mount_history.append(merged)

        # 1. Initial setup
        mgr = ProtectionManager(
            config=cfg,
            overlay_root=overlay_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
            mount_fn=tracking_mount,
        )
        mgr.setup_all()
        assert len(mount_history) == 1

        # 2. Simulate fresh reboot with a new manager instance loading manifest
        mgr_after_reboot = ProtectionManager(
            config=cfg,
            overlay_root=overlay_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
            mount_fn=tracking_mount,
        )
        res = mgr_after_reboot.remount_after_reboot()
        assert str(protect_target) in res["remounted"]
        assert len(mount_history) == 2
        assert mgr_after_reboot.targets[str(protect_target)].is_mounted is True
