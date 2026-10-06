#!/usr/bin/env python3
"""
CLI Scenario Runner
===================
Executes a simulation scenario through the complete backend pipeline without a UI:
python -m backend.app.run_scenario <scenario> --detector xgboost
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.core.pipeline import DetectionPipeline
from backend.app.core.response import SimulatedResponse


def run_cli_scenario(
    scenario: str,
    detector: str = "xgboost",
    policy: str = "immediate",
    seed: int = 42,
    speed: float = 1.0,
) -> None:
    print(f"\n=======================================================")
    print(f" AdaptShield Scenario Runner: '{scenario}'")
    print(f" Detector: {detector} | Policy: {policy} | Seed: {seed}")
    print(f"=======================================================\n")

    response_engine = SimulatedResponse(num_virtual_files=60, default_policy=policy)
    pipeline = DetectionPipeline(
        model_name=detector,
        response_engine=response_engine,
        default_policy=policy,
    )

    summary = pipeline.run_scenario(scenario=scenario, seed=seed, speed=speed)

    print(f"Scenario:             {summary['scenario']}")
    print(f"Active Detector:      {summary['detector']}")
    print(f"Random Seed:          {summary['seed']}")
    print(f"Total Windows:        {summary['total_windows']}")
    print(f"Distinct PIDs Seen:   {summary['distinct_pids']}")
    print(f"Contained PIDs:       {summary['contained_pids']}")
    
    if summary['time_to_detect_windows'] is not None:
        print(f"Time to Detect:       Window {summary['time_to_detect_windows']} ({summary['time_to_detect_seconds']:.1f}s)")
    else:
        print(f"Time to Detect:       N/A (No containments triggered)")

    print(f"Wall Execution Time:  {summary['wall_time_seconds']}s")
    print(f"Panic Switch Tripped: {summary['panic_tripped']}")

    print(f"\nVirtual Filesystem Status:")
    for status, count in summary['filesystem_status'].items():
        print(f"  - {status:12s}: {count:3d} files")

    print(f"\n-------------------------------------------------------")
    if summary['contained_pids']:
        print(f"RESULT: Attack mitigated. Contained {len(summary['contained_pids'])} malicious process(es).")
    else:
        print(f"RESULT: Clean run. Zero false containments triggered.")
    print(f"-------------------------------------------------------\n")


def main():
    parser = argparse.ArgumentParser(description="Run an AdaptShield benchmark scenario via CLI.")
    parser.add_argument("scenario", help="Scenario ID (e.g. normal_workday, nightly_backup, fast_ransomware, mixed_chaos)")
    parser.add_argument("--detector", default="xgboost", choices=["xgboost", "random_forest", "rf_tier0_ablation", "rule_based"])
    parser.add_argument("--policy", default="immediate", choices=["immediate", "manual", "none"])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--speed", type=float, default=1.0)
    args = parser.parse_args()

    run_cli_scenario(
        scenario=args.scenario,
        detector=args.detector,
        policy=args.policy,
        seed=args.seed,
        speed=args.speed,
    )


if __name__ == "__main__":
    main()
