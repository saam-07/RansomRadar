import json
import os

from adaptshield.containment_manager import (
    compute_overlay_diff, quarantine_upper, rollback_overlay,
    request_manual_decision, check_manual_decision, clear_manual_decision,
    _control_file,
)


def _make_fake_overlay_upper(tmp_path, n_files=3, content=b"x" * 100):
    upper = tmp_path / "upper"
    upper.mkdir()
    for i in range(n_files):
        (upper / f"file{i}.txt").write_bytes(content)
    return upper


def test_compute_overlay_diff_counts_files_and_bytes(tmp_path):
    upper = _make_fake_overlay_upper(tmp_path, n_files=4, content=b"y" * 50)
    total_bytes, total_files = compute_overlay_diff(str(upper))
    assert total_files == 4
    assert total_bytes == 4 * 50


def test_compute_overlay_diff_empty_dir(tmp_path):
    upper = tmp_path / "empty_upper"
    upper.mkdir()
    total_bytes, total_files = compute_overlay_diff(str(upper))
    assert total_bytes == 0
    assert total_files == 0


def test_quarantine_upper_copies_all_files_and_preserves_content(tmp_path):
    upper = _make_fake_overlay_upper(tmp_path, n_files=3, content=b"secret" * 10)
    quarantine_root = tmp_path / "quarantine"
    qpath, files_copied, bytes_copied = quarantine_upper(str(upper), str(quarantine_root), pid=1234)

    assert files_copied == 3
    assert bytes_copied == 3 * len(b"secret" * 10)
    assert os.path.exists(qpath)

    # original files must still be present in upper -- quarantine COPIES, never moves
    assert len(list(upper.glob("*.txt"))) == 3

    # quarantined copies must exist with identical content
    copied_files = list((tmp_path / "quarantine").rglob("file0.txt"))
    assert len(copied_files) == 1
    assert copied_files[0].read_bytes() == b"secret" * 10

    # manifest must be written and valid JSON
    manifest_path = list((tmp_path / "quarantine").rglob("_manifest.json"))[0]
    manifest = json.loads(manifest_path.read_text())
    assert manifest["pid"] == 1234
    assert manifest["files_copied"] == 3


def test_rollback_overlay_wipes_upper_and_work_but_recreates_empty_dirs(tmp_path):
    upper = _make_fake_overlay_upper(tmp_path, n_files=5)
    work = tmp_path / "work"
    work.mkdir()
    (work / "leftover").write_text("workdir internal state")

    rollback_overlay(str(upper), str(work))

    assert upper.exists() and list(upper.iterdir()) == []
    assert work.exists() and list(work.iterdir()) == []


def test_rollback_after_quarantine_preserves_data_via_quarantine_only(tmp_path):
    """The key reversibility property: after quarantine + rollback, the
    live upperdir is empty (filesystem restored) but the quarantine copy
    still has the pre-rollback data -- nothing is truly lost."""
    upper = _make_fake_overlay_upper(tmp_path, n_files=2, content=b"important-data")
    work = tmp_path / "work"
    work.mkdir()
    quarantine_root = tmp_path / "quarantine"

    qpath, files_copied, _ = quarantine_upper(str(upper), str(quarantine_root), pid=99)
    rollback_overlay(str(upper), str(work))

    assert list(upper.iterdir()) == []  # live state restored/empty
    quarantined_files = list((tmp_path / "quarantine").rglob("file*.txt"))
    assert len(quarantined_files) == files_copied == 2
    for f in quarantined_files:
        assert f.read_bytes() == b"important-data"


def test_manual_decision_roundtrip(tmp_path):
    control_dir = str(tmp_path / "control")
    assert check_manual_decision(control_dir, pid=42) is None  # no file yet

    request_manual_decision(control_dir, pid=42, evidence={"mod_rate": 90.0})
    assert check_manual_decision(control_dir, pid=42) is None  # status is "pending", not a decision

    f = _control_file(control_dir, 42)
    data = json.loads(f.read_text())
    data["status"] = "confirm"
    f.write_text(json.dumps(data))

    assert check_manual_decision(control_dir, pid=42) == "confirm"

    clear_manual_decision(control_dir, pid=42)
    assert check_manual_decision(control_dir, pid=42) is None
    assert not f.exists()


def test_manual_decision_ignores_unrelated_pids(tmp_path):
    control_dir = str(tmp_path / "control")
    request_manual_decision(control_dir, pid=1, evidence={})
    assert check_manual_decision(control_dir, pid=2) is None  # different pid, no file
