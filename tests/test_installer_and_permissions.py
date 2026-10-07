"""
Tests for installer permissions, operator CLI permissions, permission-error handling,
upgrade idempotency, and cgroup.freeze containment contracts.
"""
import io
import tempfile
from pathlib import Path
from unittest.mock import patch

from adaptshield.cli import main as cli_main
from adaptshield.response.containment_manager import ContainmentManager
from adaptshield.response.protection import ProtectionManager
from adaptshield.state import StateManager


def run_cli_args(*args):
    buf = io.StringIO()
    with patch("sys.argv", ["adaptshield", *args]), patch("sys.stdout", buf), patch("sys.stderr", buf):
        try:
            cli_main()
        except SystemExit:
            pass
    return buf.getvalue()


def test_installer_script_security_and_idempotency_contracts():
    """
    Validates that install.sh adheres to the security and permission architecture:
    1. System adaptshield group creation
    2. SUDO_USER idempotent addition
    3. Secure 2750 directory permissions and 640 file permissions (no world-writable)
    4. Upgrade mode (--upgrade) preserves data while reapplying permissions
    5. Native cgroup.freeze recognition without requiring subtree delegation
    """
    repo_root = Path(__file__).resolve().parent.parent
    installer_path = repo_root / "install.sh"
    assert installer_path.exists(), "install.sh must exist at repository root"

    script = installer_path.read_text(encoding="utf-8")

    # 1. Group creation
    assert "groupadd --system adaptshield" in script
    # 2. Add SUDO_USER / TARGET_USER idempotently
    assert 'usermod -aG adaptshield "$TARGET_USER"' in script
    # 3. Secure group ownership
    assert "chown -R root:adaptshield" in script
    assert "/var/lib/adaptshield" in script
    assert "/var/log/adaptshield" in script
    # 4. Secure permissions (no 777 or 666)
    assert "777" not in script
    assert "666" not in script
    assert "2750" in script
    assert "chmod 640" in script
    # 5. Upgrade flag handling & config preservation
    assert "--upgrade" in script
    assert "Preserving untouched" in script
    # 6. Native cgroup.freeze probe & backend reporting
    assert "cgroup.freeze" in script
    assert "cgroup_v2_freeze" in script


def test_cli_all_commands_graceful_permission_error_handling(monkeypatch):
    """
    Verifies that all operator CLI commands catch PermissionError and output
    clean operator guidance without generating Python tracebacks.
    """
    def mock_perm_denied(*args, **kwargs):
        raise PermissionError("Simulated permission denied for testing")

    # Test status
    monkeypatch.setattr(ProtectionManager, "load_manifest", mock_perm_denied)
    out = run_cli_args("status")
    assert "WARNING: Protection manifest or system state is not readable" in out
    assert "sudo usermod -aG adaptshield" in out
    assert "Traceback" not in out

    # Test list
    with patch.object(StateManager, "load", side_effect=PermissionError("denied")):
        out = run_cli_args("list")
    assert "WARNING: Runtime containment state at" in out
    assert "sudo usermod -aG adaptshield" in out
    assert "Traceback" not in out

    # Test show
    with patch.object(StateManager, "load", side_effect=PermissionError("denied")):
        out = run_cli_args("show", "1234")
    assert "WARNING: Runtime containment state at" in out
    assert "sudo usermod -aG adaptshield" in out
    assert "Traceback" not in out

    # Test release
    with patch.object(StateManager, "load", side_effect=PermissionError("denied")):
        out = run_cli_args("release", "1234")
    assert "ERROR: Permission denied. Releasing processes requires operator privileges" in out
    assert "Traceback" not in out

    # Test confirm
    with patch.object(StateManager, "load", side_effect=PermissionError("denied")):
        out = run_cli_args("confirm", "1234")
    assert "ERROR: Permission denied. Confirming containment requires operator privileges" in out
    assert "Traceback" not in out


def test_protection_manager_manifest_permission_resilience():
    """ProtectionManager must gracefully handle unreadable manifest file."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest_file = Path(tmp_dir) / "protection_manifest.json"
        manifest_file.write_text('{"targets": []}')

        pm = ProtectionManager(state_file=manifest_file)
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            data = pm.load_manifest()
            assert data == {}
            assert pm.manifest_permission_denied is True


def test_state_manager_permission_resilience():
    """StateManager must gracefully handle unreadable state file."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "state.json"
        state_file.write_text('{"records": {}}')

        sm = StateManager(state_file)
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            sm.load()
            assert sm.permission_denied is True
            assert sm.records == {}


def test_containment_backend_and_probe_lifecycle():
    """ContainmentManager accurately reports backend and executes safe probe."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cm = ContainmentManager(cgroup_path=Path(tmp_dir))
        backend = cm.get_backend()
        assert backend in ("cgroup_v2_freeze", "sigstop_fallback", "simulated")

        success, msg = cm.self_test()
        assert isinstance(success, bool)
        assert len(msg) > 0
