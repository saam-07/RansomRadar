"""
AdaptShield Command Line Interface (`adaptshield`).
Entry point for operator inspection, status, diagnostics, and control.
"""
from __future__ import annotations

import argparse
import os
import platform
import sys
from pathlib import Path

from .config import load_config
from .detection.tier1_bridge import is_tier1_available, get_tier1_status
from .response.containment_manager import ContainmentManager
from .ml.registry import ModelRegistry

__version__ = "0.2.0"


def cmd_version(args):
    print(f"AdaptShield version {__version__}")


def cmd_status(args):
    cfg = load_config(args.config)
    tier1_st = get_tier1_status()

    print("========================================")
    print(" AdaptShield Endpoint Agent Status")
    print("========================================")
    print(f"Version:            {__version__}")
    print(f"Operating Mode:     {cfg.mode.upper()}")
    print(f"Response Policy:    {cfg.response.policy.upper()}")
    print(f"Active Detector:    {cfg.classifier.model_name}")
    print(f"Watched Paths:      {', '.join(cfg.watch.paths)}")
    print(f"Protected Paths:    {', '.join(cfg.protect_paths)}")
    print(f"Tier-1 Subsystem:   {'ACTIVE (BCC/eBPF)' if tier1_st['available'] else 'DEGRADED (Tier-0 Only)'}")
    if not tier1_st["available"]:
        print(f"  Reason:           {tier1_st['error'] or 'BCC not installed'}")
    print(f"Log Destination:    {cfg.logging.file}")
    print(f"Alert Feed:         {cfg.logging.alert_file}")
    print("========================================")


def cmd_doctor(args):
    print("========================================")
    print(" AdaptShield System Health & Doctor")
    print("========================================")

    # 1. Operating System
    system = platform.system()
    release = platform.release()
    print(f"[*] OS Platform:     {system} {release}")
    if system == "Linux":
        print("    -> PASS: Supported operating system")
    else:
        print("    -> WARN: Running on non-Linux platform (simulated/sandbox mode)")

    # 2. Permissions / Root
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    if is_root:
        print("[*] Privileges:      root (CAP_SYS_ADMIN available) -> PASS")
    else:
        print("[*] Privileges:      non-root / unprivileged -> WARN (fanotify/cgroups require root)")

    # 3. cgroup v2 Freezer
    cm = ContainmentManager()
    if cm.is_cgroup_v2():
        print("[*] cgroup v2:       available -> PASS")
    else:
        print("[*] cgroup v2:       not mounted -> WARN (simulated freezer only)")

    # 4. BCC / eBPF
    tier1_st = get_tier1_status()
    if tier1_st["available"]:
        print("[*] BCC / eBPF:      available -> PASS")
    else:
        print(f"[*] BCC / eBPF:      not available -> INFO: {tier1_st['error'] or 'BCC missing'}")
        print("                     Degrading to Tier-0-only mode (fully supported)")

    # 5. Model Registry
    cfg = load_config(args.config)
    registry_path = Path(cfg.classifier.registry_dir)
    if registry_path.exists():
        try:
            reg = ModelRegistry(str(registry_path))
            models = reg.list_models()
            print(f"[*] Model Registry:  {len(models)} models registered -> PASS")
        except Exception as e:
            print(f"[*] Model Registry:  read failed ({e}) -> WARN")
    else:
        print("[*] Model Registry:  using default builtin models -> PASS")

    print("========================================")
    print(" Doctor check completed.")


def main():
    parser = argparse.ArgumentParser(
        prog="adaptshield",
        description="AdaptShield Autonomous Endpoint Protection CLI",
    )
    parser.add_argument("--config", "-c", default=None, help="Path to config YAML")

    subparsers = parser.add_subparsers(dest="command")

    # version
    p_ver = subparsers.add_parser("version", help="Print AdaptShield version")
    p_ver.set_defaults(func=cmd_version)

    # status
    p_status = subparsers.add_parser("status", help="Show agent runtime status and configuration")
    p_status.set_defaults(func=cmd_status)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run system diagnostics and preflight checks")
    p_doc.set_defaults(func=cmd_doctor)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
