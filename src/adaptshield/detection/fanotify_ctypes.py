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
    libc.fanotify_init.restype = ctypes.c_int
    libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]

    libc.fanotify_mark.restype = ctypes.c_int
    libc.fanotify_mark.argtypes = [
        ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
        ctypes.c_int, ctypes.c_char_p,
    ]


@dataclass
class FanotifyEvent:
    mask: int
    pid: int
    fd: int


class Fanotify:
    def __init__(self, watch_path: str):
        if not libc:
            raise OSError("libc is not available on this system")

        self.watch_path = watch_path
        self.fd = -1
        self.mode = "none"

        # Attempt 1: Modern DFID_NAME mode (Linux >= 5.9, supports create/delete/rename)
        init_flags = FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | FAN_CLOEXEC | FAN_NONBLOCK
        self.fd = libc.fanotify_init(init_flags, O_RDONLY)
        if self.fd >= 0:
            ret = libc.fanotify_mark(
                self.fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                ctypes.c_uint64(DFID_WATCH_MASK),
                -1,
                watch_path.encode(),
            )
            if ret >= 0:
                self.mode = "dfid_name"
                return
            # If mark failed with DFID_NAME mode, clean up and try fallback
            os.close(self.fd)
            self.fd = -1

        # Attempt 2: Fallback to classic fd-based fanotify (FAN_MODIFY + FAN_CLOSE_WRITE)
        init_flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK
        self.fd = libc.fanotify_init(init_flags, O_RDONLY)
        if self.fd < 0:
            errno = ctypes.get_errno()
            raise OSError(
                errno,
                os.strerror(errno)
                + " -- fanotify_init failed. Need CAP_SYS_ADMIN "
                  "(run as root / with sudo) and kernel >= 5.9.",
            )

        ret = libc.fanotify_mark(
            self.fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            ctypes.c_uint64(FD_WATCH_MASK),
            -1,
            watch_path.encode(),
        )
        if ret < 0:
            errno = ctypes.get_errno()
            os.close(self.fd)
            self.fd = -1
            raise OSError(
                errno,
                os.strerror(errno) + f" -- fanotify_mark({watch_path}) failed",
            )
        self.mode = "fd"

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

        events = []
        offset = 0
        while offset + _META_SIZE <= len(buf):
            event_len, vers, _reserved, metadata_len, mask, fd, pid = struct.unpack_from(
                _META_FMT, buf, offset
            )
            if event_len < _META_SIZE:
                break
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            events.append(FanotifyEvent(mask=mask, pid=pid, fd=fd))
            offset += event_len
        return events

    def close(self):
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1
