"""
Tier 0 -- always-on, cheap watcher.
Computes windowed features per PID without reading contents or computing entropy.
"""
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .fanotify_ctypes import (
    FAN_CLOSE_WRITE,
    FAN_CREATE,
    FAN_DELETE,
    FAN_MODIFY,
    FAN_MOVED_FROM,
    FAN_MOVED_TO,
    Fanotify,
    is_path_excluded,
)

MOD_MASK = FAN_MODIFY | FAN_CLOSE_WRITE
RENAME_MASK = FAN_MOVED_FROM | FAN_MOVED_TO
CREATE_DEL_MASK = FAN_CREATE | FAN_DELETE


@dataclass
class PidWindowState:
    events: deque = field(default_factory=lambda: deque())  # (timestamp, mask)


def gini_of_gaps(timestamps: list) -> float:
    """Gini coefficient of inter-event time gaps. 0 = perfectly even spacing, 1 = bursty."""
    if len(timestamps) < 3:
        return 0.0
    gaps = sorted(t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:]) if t2 >= t1)
    n = len(gaps)
    if n == 0 or sum(gaps) == 0:
        return 0.0
    cum = 0.0
    total = sum(gaps)
    gini_sum = 0.0
    for i, g in enumerate(gaps, start=1):
        cum += g
        gini_sum += (2 * i - n - 1) * g
    return gini_sum / (n * total)


class Tier0Watcher:
    def __init__(
        self,
        watch_path: str | list[str] = "/home",
        window_seconds: float = 2.0,
        excludes: list[str] | None = None,
        excluded_pids: set[int] | None = None,
    ):
        if isinstance(watch_path, str):
            self.watch_paths = [watch_path]
        else:
            self.watch_paths = list(watch_path)
        self.watch_path = self.watch_paths[0] if self.watch_paths else ""
        self.window_seconds = window_seconds
        self.excludes = list(excludes) if excludes else [
            "/proc", "/sys", "/dev", "/run", "/tmp",
            "/var/lib/adaptshield", "/var/log/adaptshield", "/var/cache/apt",
        ]
        self.excluded_pids = set(excluded_pids or [])
        try:
            self.excluded_pids.add(os.getpid())
        except Exception:
            pass

        try:
            self.fan = Fanotify(self.watch_paths)
        except OSError:
            self.fan = None

        self._state: dict[int, PidWindowState] = defaultdict(PidWindowState)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def record_event(
        self,
        pid: int,
        mask: int,
        path: str | None = None,
        timestamp: float | None = None,
    ):
        """Records a single filesystem event for a PID after exclusion and watch-path filtering."""
        if pid in self.excluded_pids:
            return
        if path and is_path_excluded(path, self.excludes):
            return
        if path and self.watch_paths:
            norm = os.path.abspath(path)
            matched = False
            for wp in self.watch_paths:
                norm_wp = os.path.abspath(wp)
                if norm == norm_wp or norm.startswith(norm_wp + os.sep):
                    matched = True
                    break
            if not matched:
                return

        now = timestamp if timestamp is not None else time.monotonic()
        with self._lock:
            st = self._state[pid]
            st.events.append((now, mask))

    def _reader_loop(self):
        while not self._stop.is_set():
            if not self.fan:
                time.sleep(0.05)
                continue
            try:
                events = self.fan.read_events()
            except (BlockingIOError, OSError):
                time.sleep(0.05)
                continue
            if not events:
                time.sleep(0.05)
                continue
            now = time.monotonic()
            for ev in events:
                self.record_event(ev.pid, ev.mask, path=ev.path, timestamp=now)

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self.fan:
            self.fan.close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def snapshot_features(self) -> dict[int, dict]:
        """Compute windowed features for every PID with recent activity."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        out = {}
        with self._lock:
            dead_pids = []
            for pid, st in self._state.items():
                while st.events and st.events[0][0] < cutoff:
                    st.events.popleft()
                if not st.events:
                    dead_pids.append(pid)
                    continue
                timestamps = [t for t, _m in st.events]
                mods = sum(1 for _t, m in st.events if m & MOD_MASK)
                renames = sum(1 for _t, m in st.events if m & RENAME_MASK)
                creates_dels = sum(1 for _t, m in st.events if m & CREATE_DEL_MASK)
                out[pid] = {
                    "pid": pid,
                    "window_s": self.window_seconds,
                    "mod_rate": mods / self.window_seconds,
                    "rename_rate": renames / self.window_seconds,
                    "create_del_rate": creates_dels / self.window_seconds,
                    "event_count": len(st.events),
                    "concentration_gini": gini_of_gaps(timestamps),
                }
            for pid in dead_pids:
                del self._state[pid]
        return out


def tier0_suspicion_score(features: dict) -> float:
    """Explainable escalation rule for Tier 0 features."""
    score = 0.0
    score += min(features["mod_rate"] / 50.0, 1.0) * 0.4
    score += min(features["rename_rate"] / 20.0, 1.0) * 0.3
    score += min(features["create_del_rate"] / 20.0, 1.0) * 0.1
    score += features["concentration_gini"] * 0.2
    return score
