"""
Minimal ctypes wrapper around Linux fanotify(7).
"""
import ctypes
import ctypes.util
import os
import struct
from dataclasses import dataclass

try:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
except Exception:
    libc = None

# ---- fanotify_init flags ----
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_CLASS_PRE_CONTENT = 0x00000008
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020
FAN_ENABLE_AUDIT = 0x00000040

# FID reporting modes (Linux 5.1+, 5.9+)
FAN_REPORT_TID = 0x00000100
FAN_REPORT_FID = 0x00000200
FAN_REPORT_DIR_FID = 0x00000400
FAN_REPORT_NAME = 0x00000800
FAN_REPORT_DFID_NAME = 0x00000C00  # FAN_REPORT_DIR_FID | FAN_REPORT_NAME
FAN_REPORT_PIDFD = 0x00000080

O_RDONLY = 0

# ---- fanotify_mark flags ----
FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_DONT_FOLLOW = 0x00000004
FAN_MARK_ONLYDIR = 0x00000008
FAN_MARK_MOUNT = 0x00000010
FAN_MARK_FILESYSTEM = 0x00000100
FAN_MARK_IGNORED_MASK = 0x00000020
FAN_MARK_IGNORED_SURV_MODIFY = 0x00000040

# ---- event mask flags ----
FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_DELETE_SELF = 0x00000400
FAN_MOVE_SELF = 0x00000800
FAN_OPEN_EXEC = 0x00001000

FAN_ONDIR = 0x40000000
FAN_EVENT_ON_CHILD = 0x08000000

FAN_NOFD = -1

# Info record types
FAN_EVENT_INFO_TYPE_FID = 1
FAN_EVENT_INFO_TYPE_DFID_NAME = 2
FAN_EVENT_INFO_TYPE_DFID = 3
FAN_EVENT_INFO_TYPE_PIDFD = 4

# Full mask for DFID_NAME mode
DFID_WATCH_MASK = (
    FAN_MODIFY | FAN_CLOSE_WRITE | FAN_MOVED_FROM | FAN_MOVED_TO
    | FAN_CREATE | FAN_DELETE | FAN_EVENT_ON_CHILD | FAN_ONDIR
)

# Fallback mask for legacy / standard fd mode (does not watch directory entries)
FD_WATCH_MASK = (
    FAN_MODIFY | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD
)

# struct fanotify_event_metadata (fixed-size prefix)
# __u32 event_len; __u8 vers; __u8 reserved; __u16 metadata_len;
# __aligned_u64 mask; __s32 fd; __s32 pid;
_META_FMT = "=IBBHQii"
_META_SIZE = struct.calcsize(_META_FMT)

if libc:
    try:
        libc.fanotify_init.restype = ctypes.c_int
        libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    except AttributeError:
        pass

    try:
        libc.fanotify_mark.restype = ctypes.c_int
        libc.fanotify_mark.argtypes = [
            ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
            ctypes.c_int, ctypes.c_char_p,
        ]
    except AttributeError:
        pass

    try:
        libc.open_by_handle_at.restype = ctypes.c_int
        libc.open_by_handle_at.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    except AttributeError:
        pass


def is_path_excluded(path: str, excludes: list[str]) -> bool:
    """Checks whether a given path is covered by any excluded directory."""
    if not path or not excludes:
        return False
    try:
        norm = os.path.abspath(path)
        for exc in excludes:
            norm_exc = os.path.abspath(exc)
            if norm == norm_exc or norm.startswith(norm_exc + os.sep):
                return True
    except Exception:
        pass
    return False


@dataclass
class FanotifyEvent:
    mask: int
    pid: int
    fd: int
    path: str | None = None


def parse_fanotify_buffer(
    buf: bytes,
    default_dir: str = "",
    mount_fd: int = -1,
    close_fds: bool = True,
) -> list[FanotifyEvent]:
    """
    Pure function to parse fanotify event buffer returned by os.read().
    Supports both traditional file descriptor events and modern
    FAN_REPORT_DFID_NAME / FAN_REPORT_FID directory entry events.

    For DFID_NAME events (create, delete, rename):
      - Extracts the directory entry filename from the variable-length info record.
      - Attempts path resolution via open_by_handle_at() using mount_fd.
      - Falls back to default_dir (watch path) + filename if open_by_handle_at fails or is unavailable.
      - Ensures all open fds are closed if close_fds is True.
    """
    events = []
    offset = 0
    buf_len = len(buf)

    while offset + _META_SIZE <= buf_len:
        event_len, vers, _reserved, metadata_len, mask, fd, pid = struct.unpack_from(
            _META_FMT, buf, offset
        )
        if event_len < _META_SIZE or offset + event_len > buf_len:
            break

        resolved_path = None
        extracted_name = None
        handle_buf = None

        if fd >= 0:
            try:
                resolved_path = os.readlink(f"/proc/self/fd/{fd}")
            except (OSError, AttributeError):
                resolved_path = None
            if close_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
        else:
            # Handle variable-length info records when fd == FAN_NOFD (-1)
            info_offset = offset + metadata_len
            event_end = offset + event_len

            while info_offset + 4 <= event_end:
                info_type, _pad, info_len = struct.unpack_from("=BBH", buf, info_offset)
                if info_len < 4 or info_offset + info_len > event_end:
                    break

                if info_type in (
                    FAN_EVENT_INFO_TYPE_DFID_NAME,
                    FAN_EVENT_INFO_TYPE_FID,
                    FAN_EVENT_INFO_TYPE_DFID,
                ):
                    # Record layout:
                    # [0:4]   hdr (info_type, pad, len)
                    # [4:12]  fsid (8 bytes)
                    # [12:16] handle_bytes (__u32)
                    # [16:20] handle_type (int)
                    # [20 : 20 + handle_bytes] f_handle
                    # [20 + handle_bytes : info_len] name (null-terminated string for DFID_NAME)
                    if info_len >= 20:
                        handle_bytes, handle_type = struct.unpack_from("=Ii", buf, info_offset + 12)
                        f_handle_start = info_offset + 20
                        f_handle_end = f_handle_start + handle_bytes

                        if f_handle_end <= info_offset + info_len:
                            handle_buf = buf[info_offset + 12 : f_handle_end]

                            if info_type == FAN_EVENT_INFO_TYPE_DFID_NAME:
                                name_raw = buf[f_handle_end : info_offset + info_len]
                                null_idx = name_raw.find(b"\x00")
                                name_bytes = name_raw[:null_idx] if null_idx >= 0 else name_raw
                                try:
                                    decoded_name = name_bytes.decode("utf-8", errors="replace").strip()
                                    if decoded_name and decoded_name != ".":
                                        extracted_name = decoded_name
                                except Exception:
                                    extracted_name = None

                info_offset += info_len

            # Resolve directory path via open_by_handle_at if available
            dir_path = None
            if handle_buf and libc and hasattr(libc, "open_by_handle_at") and mount_fd >= 0:
                try:
                    c_handle = ctypes.create_string_buffer(handle_buf)
                    dfd = libc.open_by_handle_at(mount_fd, ctypes.byref(c_handle), O_RDONLY)
                    if dfd >= 0:
                        try:
                            dir_path = os.readlink(f"/proc/self/fd/{dfd}")
                        except (OSError, AttributeError):
                            dir_path = None
                        finally:
                            try:
                                os.close(dfd)
                            except OSError:
                                pass
                except Exception:
                    dir_path = None

            # Fall back to default_dir + extracted_name if open_by_handle_at fails or is unavailable
            if dir_path and extracted_name:
                resolved_path = os.path.join(dir_path, extracted_name)
            elif dir_path:
                resolved_path = dir_path
            elif default_dir and extracted_name:
                resolved_path = os.path.join(default_dir, extracted_name)
            elif extracted_name:
                resolved_path = extracted_name
            elif default_dir:
                resolved_path = default_dir

        events.append(FanotifyEvent(mask=mask, pid=pid, fd=fd, path=resolved_path))
        offset += event_len

    return events


class Fanotify:
    """
    Multi-path fanotify watcher for Linux filesystems.
    Watches configured include paths, reports per-event PID and paths,
    and supports dynamic mark attachment.
    """
    def __init__(self, watch_paths: str | list[str]):
        if not libc:
            raise OSError("libc is not available on this system")

        if isinstance(watch_paths, str):
            self.watch_paths = [watch_paths]
        else:
            self.watch_paths = list(watch_paths)

        self.watch_path = self.watch_paths[0] if self.watch_paths else ""
        self.fd = -1
        self.mode = "none"
        self.marked_paths: list[str] = []
        self.failed_paths: dict[str, str] = {}
        self.mount_fd = -1

        if not self.watch_paths:
            return

        # Attempt to open directory descriptor for open_by_handle_at path resolution
        try:
            if self.watch_path and os.path.exists(self.watch_path):
                self.mount_fd = os.open(self.watch_path, os.O_RDONLY | getattr(os, "O_PATH", 0))
        except Exception:
            self.mount_fd = -1

        # Attempt 1: Modern DFID_NAME mode (Linux >= 5.9, supports create/delete/rename)
        init_flags = FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | FAN_CLOEXEC | FAN_NONBLOCK
        self.fd = libc.fanotify_init(init_flags, O_RDONLY)
        if self.fd >= 0:
            success = False
            for path in self.watch_paths:
                ret = libc.fanotify_mark(
                    self.fd,
                    FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                    ctypes.c_uint64(DFID_WATCH_MASK),
                    -1,
                    path.encode(),
                )
                if ret >= 0:
                    self.marked_paths.append(path)
                    success = True
                else:
                    self.failed_paths[path] = f"fanotify_mark DFID_NAME errno {ctypes.get_errno()}"
            if success:
                self.mode = "dfid_name"
                return
            # If all marks failed in DFID_NAME mode, close and try fallback
            os.close(self.fd)
            self.fd = -1

        # Attempt 2: Fallback to classic fd-based fanotify (FAN_MODIFY + FAN_CLOSE_WRITE)
        init_flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
        self.fd = libc.fanotify_init(init_flags, O_RDONLY)
        if self.fd < 0:
            errno = ctypes.get_errno()
            if self.mount_fd >= 0:
                os.close(self.mount_fd)
                self.mount_fd = -1
            raise OSError(
                errno,
                os.strerror(errno)
                + " -- fanotify_init failed. Need CAP_SYS_ADMIN "
                  "(run as root / with sudo) and kernel >= 5.9.",
            )

        self.marked_paths.clear()
        for path in self.watch_paths:
            ret = libc.fanotify_mark(
                self.fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                ctypes.c_uint64(FD_WATCH_MASK),
                -1,
                path.encode(),
            )
            if ret >= 0:
                self.marked_paths.append(path)
            else:
                self.failed_paths[path] = f"fanotify_mark FD errno {ctypes.get_errno()}"

        if not self.marked_paths and self.watch_paths:
            errno = ctypes.get_errno()
            os.close(self.fd)
            self.fd = -1
            if self.mount_fd >= 0:
                os.close(self.mount_fd)
                self.mount_fd = -1
            raise OSError(
                errno,
                os.strerror(errno) + f" -- fanotify_mark failed on all paths: {self.watch_paths}",
            )
        self.mode = "fd"

    def add_watch_path(self, path: str) -> bool:
        """Dynamically add an additional watch path to an active fanotify descriptor."""
        if self.fd < 0:
            return False
        mask = DFID_WATCH_MASK if self.mode == "dfid_name" else FD_WATCH_MASK
        ret = libc.fanotify_mark(
            self.fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            ctypes.c_uint64(mask),
            -1,
            path.encode(),
        )
        if ret >= 0:
            if path not in self.watch_paths:
                self.watch_paths.append(path)
            if path not in self.marked_paths:
                self.marked_paths.append(path)
            return True
        self.failed_paths[path] = f"fanotify_mark errno {ctypes.get_errno()}"
        return False

    def read_events(self, bufsize: int = 65536) -> list[FanotifyEvent]:
        if self.fd < 0:
            return []
        try:
            buf = os.read(self.fd, bufsize)
        except BlockingIOError:
            return []
        except OSError as e:
            if e.errno in (11, 35):  # EAGAIN / EWOULDBLOCK
                return []
            raise

        return parse_fanotify_buffer(
            buf, default_dir=self.watch_path, mount_fd=self.mount_fd, close_fds=True
        )

    def close(self):
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1
        if self.mount_fd >= 0:
            try:
                os.close(self.mount_fd)
            except OSError:
                pass
            self.mount_fd = -1
