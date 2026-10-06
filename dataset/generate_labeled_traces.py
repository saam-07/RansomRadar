"""
Drives one (workload x filesystem x seed) trace generation run:
  1. resets the target filesystem/overlay to pristine state
  2. starts the AdaptShield daemon in "collect only, don't classify" logging mode
     is not needed for TRAINING data -- for training, we run tier0+tier1
     collection directly (no classifier in the loop) and write raw feature
     rows with the KNOWN ground-truth label attached, which is what
     classifier.py's fit() consumes.
  3. runs the requested workload
  4. stops collection, writes results/raw/traces_<workload>_<fs>_<seed>.csv
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

import pandas as pd

from adaptshield.tier0_watcher import Tier0Watcher
from adaptshield.tier1_bridge import Tier1Tracer
from adaptshield.feature_aggregator import FeatureAggregator


WORKLOAD_LABEL = {
    "benign": "benign",
    "backup_rsync": "backup",
    "backup_tar": "backup",
    "oltp_mysql": "oltp",
    "oltp_pgsql": "oltp",
    "ransomware_full": "ransomware",
    "ransomware_partial": "ransomware",
    "ransomware_intermittent": "ransomware",
}


def collect_trace(watch_path: str, duration_s: float, window_s: float,
                   workload_cmd: list[str], label: str, seed: int,
                   out_csv: str):
    tier0 = Tier0Watcher(watch_path, window_seconds=window_s)
    tier1 = Tier1Tracer()
    agg = FeatureAggregator(window_seconds=window_s)
    tier0.start()

    # For DATASET GENERATION (unlike live deployment) we trace every PID
    # at Tier-1 resolution from t=0, because we need ground-truth features
    # for the escalated tier too, to train the classifier that later DECIDES
    # when to escalate. This is a one-time cost paid during data collection,
    # not during deployment.
    proc = subprocess.Popen(workload_cmd)
    tier1.escalate(proc.pid)

    rows = []
    t_end = time.monotonic() + duration_s
    while time.monotonic() < t_end and proc.poll() is None:
        tier1.poll(timeout_ms=int(window_s * 1000))
        agg.add_tier1_events(tier1.drain_events())
        snapshot = tier0.snapshot_features()
        for row in agg.build_rows(snapshot):
            row["label"] = label
            row["seed"] = seed
            row["workload_cmd"] = " ".join(workload_cmd)
            rows.append(row)

    proc.wait(timeout=30)
    tier0.stop()

    df = pd.DataFrame(rows)
    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_csv, index=False)
    print(f"Wrote {len(df)} rows to {out_csv}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", required=True)
    ap.add_argument("--workload", required=True, choices=list(WORKLOAD_LABEL.keys()))
    ap.add_argument("--workload-cmd", required=True, nargs=argparse.REMAINDER,
                     help="the actual command to run, e.g. -- python3 dataset/ransomware_sim.py ...")
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--window", type=float, default=2.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    label = WORKLOAD_LABEL[args.workload]
    cmd = args.workload_cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    collect_trace(args.watch, args.duration, args.window, cmd, label, args.seed, args.out)


if __name__ == "__main__":
    main()
