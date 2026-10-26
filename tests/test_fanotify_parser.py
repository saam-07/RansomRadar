import struct
import os
from adaptshield.detection.fanotify_ctypes import (
    parse_fanotify_buffer,
    _META_FMT,
    _META_SIZE,
    FAN_MODIFY,
    FAN_CREATE,
    FAN_DELETE,
    FAN_MOVED_TO,
    FAN_NOFD,
    FAN_EVENT_INFO_TYPE_DFID_NAME,
)


def _craft_dfid_name_event(mask: int, pid: int, filename: str, handle_bytes: bytes = b"HANDLE01") -> bytes:
    """Helper to craft a realistic fanotify buffer with FAN_REPORT_DFID_NAME info record."""
    name_bytes = filename.encode("utf-8") + b"\x00"
    # Align to 4 bytes
    pad_len = (4 - (len(name_bytes) % 4)) % 4
    name_padded = name_bytes + (b"\x00" * pad_len)

    # Info record:
    # hdr: u8 info_type, u8 pad, u16 len
    # fsid: 8 bytes
    # file_handle: u32 handle_bytes, int handle_type, handle data
    # name string
    info_len = 4 + 8 + 8 + len(handle_bytes) + len(name_padded)
    info_hdr = struct.pack("=BBH", FAN_EVENT_INFO_TYPE_DFID_NAME, 0, info_len)
    fsid = b"\x01\x00\x00\x00\x02\x00\x00\x00"
    fh_hdr = struct.pack("=Ii", len(handle_bytes), 1)

    info_body = info_hdr + fsid + fh_hdr + handle_bytes + name_padded

    event_len = _META_SIZE + len(info_body)
    meta = struct.pack(_META_FMT, event_len, 3, 0, _META_SIZE, mask, FAN_NOFD, pid)
    return meta + info_body


def test_parse_classic_fd_event():
    # Standard metadata event without info records
    meta = struct.pack(_META_FMT, _META_SIZE, 3, 0, _META_SIZE, FAN_MODIFY, -1, 4242)
    events = parse_fanotify_buffer(meta, default_dir="/mnt/testfs", close_fds=False)
    assert len(events) == 1
    assert events[0].mask == FAN_MODIFY
    assert events[0].pid == 4242
    assert events[0].fd == -1
    assert events[0].path == "/mnt/testfs"


def test_parse_dfid_name_create_event():
    buf = _craft_dfid_name_event(
        mask=FAN_CREATE,
        pid=1001,
        filename="ransom_note.txt",
    )
    events = parse_fanotify_buffer(buf, default_dir="/mnt/testfs_ext4", mount_fd=-1)
    assert len(events) == 1
    ev = events[0]
    assert ev.mask == FAN_CREATE
    assert ev.pid == 1001
    assert ev.fd == FAN_NOFD
    assert ev.path == os.path.join("/mnt/testfs_ext4", "ransom_note.txt")


def test_parse_dfid_name_rename_event():
    buf = _craft_dfid_name_event(
        mask=FAN_MOVED_TO,
        pid=1002,
        filename="financial_records.xlsx.locked",
    )
    events = parse_fanotify_buffer(buf, default_dir="/home/user/docs", mount_fd=-1)
    assert len(events) == 1
    ev = events[0]
    assert ev.mask == FAN_MOVED_TO
    assert ev.pid == 1002
    assert ev.path == os.path.join("/home/user/docs", "financial_records.xlsx.locked")


def test_parse_dfid_name_delete_event():
    buf = _craft_dfid_name_event(
        mask=FAN_DELETE,
        pid=1003,
        filename="shadow_copy.bak",
    )
    events = parse_fanotify_buffer(buf, default_dir="/var/data", mount_fd=-1)
    assert len(events) == 1
    ev = events[0]
    assert ev.mask == FAN_DELETE
    assert ev.pid == 1003
    assert ev.path == os.path.join("/var/data", "shadow_copy.bak")


def test_parse_multiple_events_in_buffer():
    buf1 = _craft_dfid_name_event(FAN_CREATE, 2001, "file1.txt")
    buf2 = _craft_dfid_name_event(FAN_MOVED_TO, 2001, "file1.txt.enc")
    meta3 = struct.pack(_META_FMT, _META_SIZE, 3, 0, _META_SIZE, FAN_MODIFY, -1, 2001)

    combined = buf1 + buf2 + meta3
    events = parse_fanotify_buffer(combined, default_dir="/mnt/testfs", mount_fd=-1)
    assert len(events) == 3
    assert events[0].path == os.path.join("/mnt/testfs", "file1.txt")
    assert events[1].path == os.path.join("/mnt/testfs", "file1.txt.enc")
    assert events[2].mask == FAN_MODIFY


def test_parse_truncated_or_malformed_buffer_does_not_crash():
    assert parse_fanotify_buffer(b"") == []
    assert parse_fanotify_buffer(b"short") == []
    # Partial metadata header
    assert parse_fanotify_buffer(b"\x00" * 15) == []
    # Metadata claiming large length but buffer truncated
    bad_meta = struct.pack(_META_FMT, 100, 3, 0, _META_SIZE, FAN_CREATE, -1, 999)
    assert parse_fanotify_buffer(bad_meta) == []
