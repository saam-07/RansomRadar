"""
Drives the full experimental matrix (roadmap Sec 7.1):
  4 workloads x 3 filesystems x 4 configurations x 10 seeds = 480 runs
plus the window-size sweep (AdaptShield only) = 180 more runs.

This script is DELIBERATELY conservative and explicit rather than clever:
every run is logged with its exact seed, config, and command, so any
single result row is independently reproducible by re-running one line
from configs/*.yaml.

Usage:
    sudo .venv/bin/python -m experiments.experiment_runner --config experiments/configs/full_matrix.yaml
"""
import argparse
import csv
import subprocess
import time
from pathlib import Path

import yaml

import os

FS_MOUNTS = {
    "ext4": "/mnt/testfs_ext4",
    "btrfs": "/mnt/testfs_btrfs",
    "xfs": "/mnt/testfs_xfs",
}
# Must match the IMG_DIR used in setup/make_test_filesystems.sh
# (default: $HOME/adaptshield_fsimages). Override by setting the
# ADAPTSHIELD_FSIMAGES_DIR environment variable if you customized it.
_FSIMG_DIR = os.environ.get("ADAPTSHIELD_FSIMAGES_DIR",
                             os.path.expanduser("~/adaptshield_fsimages"))
FS_IMAGES = {
    "ext4": f"{_FSIMG_DIR}/testfs_ext4.img",
    "btrfs": f"{_FSIMG_DIR}/testfs_btrfs.img",
    "xfs": f"{_FSIMG_DIR}/testfs_xfs.img",
}
MKFS = {"ext4": "mkfs.ext4 -F", "btrfs": "mkfs.btrfs -f", "xfs": "mkfs.xfs -f"}

WORKLOAD_COMMANDS = {
    "benign": lambda mnt, seed: ["python3", "dataset/benign_edit_mix.py", "--dir", mnt, "--seed", str(seed)],
    "backup": lambda mnt, seed: ["python3", "dataset/benign_workloads.py", "rsync",
                                  "--src", mnt + "/data", "--dst", mnt + "/backup"],
    "oltp": lambda mnt, seed: ["python3", "dataset/benign_workloads.py", "sysbench",
                                "--driver", "mysql", "--duration", "60"],
    "ransomware": lambda mnt, seed: ["python3", "dataset/ransomware_sim.py",
                                      "--target-dir", mnt + "/data", "--mode", "full",
                                      "--rate", "20", "--seed", str(seed)],
}

CONFIGS = {
    "rule_based": ["python3", "-m", "baselines.rule_based_baseline"],
    "always_on_tier1": ["python3", "-m", "baselines.always_on_tier1_baseline"],
    "ml_no_escalation": ["python3", "-m", "baselines.ml_no_escalation_baseline"],
    "adaptshield": ["python3", "-m", "adaptshield.daemon", "--classifier", "xgboost",
                    "--rollback-policy", "none"],
    # New: same detection pipeline as "adaptshield" above, but with
    # IMMEDIATE reversible containment enabled -- this is the
    # configuration that actually produces "bytes saved by rollback" /
    # "quarantined files" numbers for roadmap Sec 7.6 fig 4. Compare
    # against "adaptshield" (freeze-only) to isolate what rollback adds.
    "adaptshield_reversible": ["python3", "-m", "adaptshield.daemon", "--classifier", "xgboost",
                               "--rollback-policy", "immediate"],
}


def reset_filesystem(fs: str):
    mnt = FS_MOUNTS[fs]
    img = FS_IMAGES[fs]
    subprocess.run(["umount", "-f", mnt], check=False)
    subprocess.run(MKFS[fs].split() + [img], check=True)
    subprocess.run(["mount", "-o", "loop", img, mnt], check=True)
    subprocess.run(["chmod", "-R", "777", mnt], check=False)
    Path(mnt, "data").mkdir(exist_ok=True)
    Path(mnt, "backup").mkdir(exist_ok=True)
    Path(mnt, ".overlay_upper").mkdir(exist_ok=True)
    Path(mnt, ".overlay_work").mkdir(exist_ok=True)
    Path(mnt, ".quarantine").mkdir(exist_ok=True)
    Path(mnt, "merged").mkdir(exist_ok=True)
    subprocess.run(["chmod", "-R", "777", mnt], check=False)



def run_cell(workload: str, fs: str, config: str, seed: int, window: float,
             duration_s: float, results_writer):
    mnt = FS_MOUNTS[fs]
    reset_filesystem(fs)

    cell_tag = f"{workload}_{fs}_{config}_{seed}"
    daemon_cmd = CONFIGS[config] + [
        "--watch", mnt,
        "--overlay-upper", mnt + "/.overlay_upper",
        "--overlay-work", mnt + "/.overlay_work",
        "--quarantine-dir", f"results/processed/quarantine/{cell_tag}",
        "--control-dir", f"results/raw/control/{cell_tag}",
        "--window", str(window), "--log", f"results/raw/{cell_tag}.jsonl",
    ]
    daemon_proc = subprocess.Popen(daemon_cmd)
    time.sleep(2.0)  # let the daemon attach fully before starting the workload

    overhead_csv = f"results/raw/overhead_{cell_tag}.csv"
    overhead_proc = subprocess.Popen([
        "python3", "instrumentation/overhead_monitor.py",
        "--pid", str(daemon_proc.pid), "--out", overhead_csv,
    ])

    t0 = time.monotonic()
    workload_cmd = WORKLOAD_COMMANDS[workload](mnt, seed)
    subprocess.run(workload_cmd, timeout=duration_s + 30)
    elapsed = time.monotonic() - t0

    daemon_proc.terminate()
    overhead_proc.terminate()
    daemon_proc.wait(timeout=10)
    overhead_proc.wait(timeout=10)

    results_writer.writerow({
        "workload": workload, "filesystem": fs, "config": config, "seed": seed,
        "window_s": window, "elapsed_s": elapsed,
        "log_path": f"results/raw/{cell_tag}.jsonl",
        "overhead_csv": overhead_csv,
    })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="YAML file listing seeds/duration/window")
    args = ap.parse_args()
    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    Path("results/raw").mkdir(parents=True, exist_ok=True)
    manifest_path = "results/raw/manifest.csv"
    with open(manifest_path, "w", newline="") as mf:
        writer = csv.DictWriter(mf, fieldnames=[
            "workload", "filesystem", "config", "seed", "window_s",
            "elapsed_s", "log_path", "overhead_csv",
        ])
        writer.writeheader()
        for workload in cfg["workloads"]:
            for fs in cfg["filesystems"]:
                for config in cfg["configurations"]:
                    for seed in range(cfg["seeds_per_cell"]):
                        print(f"=== {workload} / {fs} / {config} / seed={seed} ===")
                        run_cell(workload, fs, config, seed,
                                 window=cfg["window_s"], duration_s=cfg["duration_s"],
                                 results_writer=writer)
                        mf.flush()
    print(f"Done. Manifest written to {manifest_path}")


if __name__ == "__main__":
    main()
