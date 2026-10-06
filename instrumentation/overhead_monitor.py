"""
Samples CPU% and RSS of the AdaptShield daemon process at 1Hz, for the
overhead-vs-accuracy trade-off metric (roadmap Sec 7.3/7.6 fig 2).
Run this alongside daemon.py, pointed at its PID.
"""
import argparse
import csv
import time
from pathlib import Path

import psutil


def monitor(pid: int, out_csv: str, interval_s: float = 1.0):
    proc = psutil.Process(pid)
    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ts", "cpu_percent", "rss_bytes", "num_threads"])
        proc.cpu_percent(interval=None)  # prime the internal counter
        try:
            while proc.is_running():
                time.sleep(interval_s)
                writer.writerow([
                    time.time(),
                    proc.cpu_percent(interval=None),
                    proc.memory_info().rss,
                    proc.num_threads(),
                ])
                f.flush()
        except (psutil.NoSuchProcess, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()
    monitor(args.pid, args.out, args.interval)
