"""
Tier 0 -- always-on, cheap watcher.

Computes, per PID, over a sliding window:
  - modification rate      (FAN_MODIFY + FAN_CLOSE_WRITE events / sec)
  - rename rate             (FAN_MOVED_FROM + FAN_MOVED_TO events / sec)
  - create/delete rate
  - distinct file count touched in the window
  - temporal concentration  (Gini coefficient of inter-event gaps -- high
                              concentration = bursty = more ransomware-like)

This module must stay cheap: no entropy computation, no content reads.
That is Tier 1's job (see tier1_bridge.py / ebpf/tier1_trace.bpf.c).
"""
import argparse
import sys
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .fanotify_ctypes import (
    Fanotify, FAN_MODIFY, FAN_CLOSE_WRITE, FAN_MOVED_FROM, FAN_MOVED_TO,
    FAN_CREATE, FAN_DELETE,
)

MOD_MASK = FAN_MODIFY | FAN_CLOSE_WRITE
RENAME_MASK = FAN_MOVED_FROM | FAN_MOVED_TO
CREATE_DEL_MASK = FAN_CREATE | FAN_DELETE


@dataclass
class PidWindowState:
    events: deque = field(default_factory=lambda: deque())  # (timestamp, mask)


def gini_of_gaps(timestamps: list) -> float:
    """Gini coefficient of inter-event time gaps. 0 = perfectly even spacing
    (looks like normal usage), 1 = extremely bursty (looks like an attack
    dumping thousands of writes almost simultaneously)."""
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
    def __init__(self, watch_path: str, window_seconds: float = 2.0):
        self.fan = Fanotify(watch_path)
        self.window_seconds = window_seconds
        self._state: dict[int, PidWindowState] = defaultdict(PidWindowState)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def _reader_loop(self):
        while not self._stop.is_set():
            try:
                events = self.fan.read_events()
            except (BlockingIOError, OSError):
                time.sleep(0.05)
                continue
            if not events:
                time.sleep(0.05)
                continue
            now = time.monotonic()
            with self._lock:
                for ev in events:
                    st = self._state[ev.pid]
                    st.events.append((now, ev.mask))

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.fan.close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def snapshot_features(self) -> dict[int, dict]:
        """Compute windowed features for every PID with recent activity,
        and prune events older than window_seconds."""
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
    """A simple, explainable, EXPLICITLY-DOCUMENTED escalation rule.
    This function is intentionally one of the ablation targets in Sec 8
    of the roadmap -- do not silently tune it without logging the change.
    """
    score = 0.0
    score += min(features["mod_rate"] / 50.0, 1.0) * 0.4
    score += min(features["rename_rate"] / 20.0, 1.0) * 0.3
    score += min(features["create_del_rate"] / 20.0, 1.0) * 0.1
    score += features["concentration_gini"] * 0.2
    return score  # in [0, 1]; escalation threshold theta0 is swept in experiments


def main():
    ap = argparse.ArgumentParser(description="Run Tier 0 fanotify watcher in standalone mode.")
    ap.add_argument("--watch", default="/mnt/testfs_ext4", help="Mount/path to watch (default: /mnt/testfs_ext4)")
    ap.add_argument("--window", type=float, default=2.0, help="Sliding window size in seconds (default: 2.0)")
    ap.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds (default: 1.0)")
    args = ap.parse_args()

    print(f"[Tier 0 Watcher] Initializing watcher on: {args.watch} (window={args.window}s)...")
    try:
        watcher = Tier0Watcher(args.watch, window_seconds=args.window)
    except Exception as e:
        print(f"Error starting Tier0Watcher: {e}")
        print("Note: fanotify requires root privileges (run with sudo) and a valid mount path.")
        sys.exit(1)

    watcher.start()
    print(f"[Tier 0 Watcher] Mode: {watcher.fan.mode}. Listening for file activity (Press Ctrl+C to stop)...")
    try:
        while True:
            time.sleep(args.interval)
            snap = watcher.snapshot_features()
            if snap:
                print(f"\n--- {time.strftime('%H:%M:%S')} Active PIDs: {len(snap)} ---")
                for pid, feats in snap.items():
                    score = tier0_suspicion_score(feats)
                    print(
                        f"PID {pid:6d} | mod_rate: {feats['mod_rate']:6.1f}/s | "
                        f"rename_rate: {feats['rename_rate']:6.1f}/s | "
                        f"create_del: {feats['create_del_rate']:6.1f}/s | "
                        f"gini: {feats['concentration_gini']:.3f} | "
                        f"events: {feats['event_count']:4d} | "
                        f"SUSPICION: {score:.3f}"
                    )
    except KeyboardInterrupt:
        print("\nStopping Tier 0 watcher...")
    finally:
        watcher.stop()
        print("Tier 0 watcher stopped.")


if __name__ == "__main__":
    main()
