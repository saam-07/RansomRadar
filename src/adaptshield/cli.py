"""
AdaptShield Unified Command Line Interface (`adaptshield`).

Complete operator control tool providing:
- status: Agent state, operating mode, policy, paths, rollback availability, active detector.
- doctor: Deep preflight diagnostics (kernel, cgroup v2, freezer, fanotify, BCC, root, model).
- run: Foreground agent daemon run (what systemd executes; supports --dry-run).
- alerts: View, filter (--since, --json), and tail (--follow) forensic alerts.
- list: List currently contained and pending operator-decision PIDs.
- show: Display forensic evidence and anomaly contributions for a contained PID.
- release: Manual decision false-positive release / thaw.
- confirm: Manual decision true-positive confirmation (quarantine + rollback + kill).
- mode: View or modify operating mode (monitor | protect | learn).
- config: Configuration operations (check | show | edit).
- allowlist: Manage protected allowlists (list | add | remove).
- model: Model registry operations (list | info | set | reload | rollback).
- train: Train detectors on labeled trace data.
- evaluate: Evaluate trained detectors on test splits.
- simulate: Safely run benign or ransomware workload simulations in a sandbox directory.
- version: Print package version.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .config import AdaptShieldConfig, load_config
from .daemon import AdaptShieldDaemon
from .detection.tier1_bridge import get_tier1_status, is_tier1_available
from .logging.logger import get_logger, setup_logging
from .ml.classifier import build_classifier
from .ml.registry import ModelRegistry
from .ml.schema import FEATURE_COLUMNS, validate_features
from .ml.selector import select_classifier
from .response.containment_manager import (
    ContainmentManager,
    RollbackPolicy,
    check_manual_decision,
    clear_manual_decision,
    resolve_manual_decision,
    unfreeze_pid,
)
from .response.protection import ProtectionManager
from .state import StateManager

__version__ = "0.2.0"
logger = get_logger("adaptshield.cli")


# -----------------------------------------------------------------------------
# 1. Version & Status & Doctor
# -----------------------------------------------------------------------------

def cmd_version(args):
    print(f"AdaptShield version {__version__}")


def cmd_status(args):
    cfg = load_config(args.config)
    tier1_st = get_tier1_status()

    # Protection manager status
    prot_mgr = ProtectionManager(config=cfg)
    prot_mgr.load_manifest()
    prot_st = prot_mgr.get_status()

    # State manager
    state_file = Path(cfg.response.control_dir).parent / "state.json"
    state_mgr = StateManager(state_file)
    contained_pids = [p for p, r in state_mgr.records.items() if r.status in ("frozen", "awaiting_manual")]

    print("=" * 64)
    print(" AdaptShield Endpoint Agent Status")
    print("=" * 64)
    print(f"Version:              {__version__}")
    print(f"Operating Mode:       {cfg.mode.upper()}")
    print(f"Monitor-First Window: {cfg.monitor_first_period_hours} hours")
    print(f"Response Policy:      {cfg.response.policy.upper()} (auto-resolve: {cfg.response.auto_resolve_after_seconds}s -> {cfg.response.auto_resolve_action})")
    print(f"Active Detector:      {cfg.classifier.model_name} (mode: {cfg.classifier.mode})")
    print(f"Allow Synthetic:      {cfg.classifier.allow_synthetic}")
    print(f"Watched Paths:        {', '.join(cfg.watch.paths)}")
    print(f"Excluded Paths:       {', '.join(cfg.watch.excludes[:4])} ... ({len(cfg.watch.excludes)} total)")
    print(f"Protected Paths:      {', '.join(cfg.protect_paths)}")
    print(f"Rollback Status:      {'AVAILABLE' if prot_st['rollback_globally_available'] else 'DEGRADED / FALLBACK ONLY'}")
    print(f"Tier-1 eBPF:          {'ACTIVE' if tier1_st['available'] else 'DEGRADED (Tier-0 Only)'}")
    if not tier1_st["available"]:
        print(f"  Tier-1 Reason:      {tier1_st['error'] or 'BCC not installed'}")
    print(f"Contained PIDs:       {len(contained_pids)} active ({contained_pids if contained_pids else 'none'})")
    print(f"Log Destination:      {cfg.logging.file}")
    print(f"Alert Feed:           {cfg.logging.alert_file}")
    print("=" * 64)


def cmd_doctor(args):
    cfg = load_config(args.config)
    print("=" * 64)
    print(" AdaptShield Preflight Health & Diagnostics")
    print("=" * 64)

    # 1. OS & Kernel
    system = platform.system()
    release = platform.release()
    print(f"[*] OS Platform:         {system} {release}")
    if system == "Linux":
        print("    -> PASS: Supported operating system")
    else:
        print("    -> WARN: Running on non-Linux platform (simulated/sandbox mode)")

    # 2. Root / Privileges
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    if is_root:
        print("[*] Privileges:          root (CAP_SYS_ADMIN available) -> PASS")
    else:
        print("[*] Privileges:          non-root / unprivileged -> WARN (cgroups & fanotify require root)")

    # 3. cgroup v2 & Freezer
    cm = ContainmentManager()
    if cm.is_cgroup_v2():
        print("[*] cgroup v2:           mounted at /sys/fs/cgroup -> PASS")
        controllers = (Path("/sys/fs/cgroup/cgroup.controllers")).read_text()
        if "freezer" in controllers:
            print("[*] cgroup freezer:      supported in root cgroup -> PASS")
        else:
            print("[*] cgroup freezer:      freezer controller not enabled -> WARN")
    else:
        print("[*] cgroup v2:           not detected -> WARN (simulated freezer only)")

    # 4. fanotify
    if system == "Linux":
        fan_exists = Path("/proc/sys/fs/fanotify").exists()
        if fan_exists:
            print("[*] fanotify subsystem:  available -> PASS")
        else:
            print("[*] fanotify subsystem:  not detected -> WARN")
    else:
        print("[*] fanotify subsystem:  unsupported on non-Linux -> WARN")

    # 5. BCC / eBPF
    tier1_st = get_tier1_status()
    if tier1_st["available"]:
        print("[*] BCC / eBPF:          available -> PASS")
    else:
        print(f"[*] BCC / eBPF:          unavailable ({tier1_st['error'] or 'BCC missing'}) -> INFO: Tier-0-only mode active")

    # 6. Classifier & Registry
    try:
        clf, meta = select_classifier(cfg)
        status_str = "PASS" if not meta.get("fallback_used") else "WARN (Fallback active)"
        print(f"[*] Active Detector:     {meta.get('name')} (synthetic={meta.get('synthetic')}) -> {status_str}")
        if meta.get("fallback_used"):
            print(f"    Fallback Reason:     {meta.get('fallback_reason')}")
    except Exception as e:
        print(f"[*] Active Detector:     failed to load ({e}) -> FAIL")

    print("=" * 64)
    print(" Doctor diagnostics completed.")


# -----------------------------------------------------------------------------
# 2. Foreground Run
# -----------------------------------------------------------------------------

def cmd_run(args):
    cfg = load_config(args.config)
    setup_logging(
        level=cfg.logging.level,
        log_file=cfg.logging.file,
        max_bytes=cfg.logging.max_bytes,
        backup_count=cfg.logging.backup_count,
        use_journald=cfg.logging.use_journald,
    )
    logger.info("Starting AdaptShield in foreground (dry-run=%s)...", args.dry_run)
    daemon = AdaptShieldDaemon.from_config(cfg, dry_run=args.dry_run)
    daemon.run_forever()


# -----------------------------------------------------------------------------
# 3. Alerts
# -----------------------------------------------------------------------------

def _parse_duration(since_str: str) -> float:
    """Parses duration strings like 1h, 30m, 10s into seconds."""
    since_str = since_str.strip().lower()
    if since_str.endswith("h"):
        return float(since_str[:-1]) * 3600
    if since_str.endswith("m"):
        return float(since_str[:-1]) * 60
    if since_str.endswith("s"):
        return float(since_str[:-1])
    if since_str.endswith("d"):
        return float(since_str[:-1]) * 86400
    return float(since_str)


def cmd_alerts(args):
    cfg = load_config(args.config)
    alert_file = Path(cfg.logging.alert_file)

    if not alert_file.exists():
        print(f"No alerts log found at {alert_file}.")
        return

    cutoff = 0.0
    if args.since:
        try:
            delta = _parse_duration(args.since)
            cutoff = time.time() - delta
        except Exception:
            print(f"Invalid duration format for --since: '{args.since}'. Use e.g. 1h, 30m.")
            return

    def print_alert(line_text: str):
        if not line_text.strip():
            return
        try:
            record = json.loads(line_text)
            ts = record.get("timestamp", 0.0)
            if cutoff and ts < cutoff:
                return

            if args.json:
                print(json.dumps(record))
            else:
                timestr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                ev = record.get("event", "ALERT")
                pid = record.get("pid", "N/A")
                score = record.get("risk_ewma", 0.0)
                expl = record.get("explanation", {})
                summary = expl.get("summary", "No details")
                print(f"[{timestr}] {ev:<15} PID={pid:<6} Risk={score:.2f} | {summary}")
        except Exception:
            pass

    if args.follow:
        print(f"Tailing alerts from {alert_file} (Ctrl+C to stop)...")
        with open(alert_file, "r", encoding="utf-8") as f:
            # First dump existing matches
            for line in f:
                print_alert(line)
            # Then follow new lines
            while True:
                line = f.readline()
                if line:
                    print_alert(line)
                else:
                    time.sleep(0.5)
    else:
        with open(alert_file, "r", encoding="utf-8") as f:
            for line in f:
                print_alert(line)


# -----------------------------------------------------------------------------
# 4. Containment: list, show, release, confirm
# -----------------------------------------------------------------------------

def cmd_list(args):
    cfg = load_config(args.config)
    state_file = Path(cfg.response.control_dir).parent / "state.json"
    state_mgr = StateManager(state_file)
    active = [r for r in state_mgr.records.values() if r.status in ("frozen", "awaiting_manual")]

    if not active:
        print("No contained or pending processes found.")
        return

    print("=" * 64)
    print(f"{'PID':<8} {'STATUS':<16} {'POLICY':<10} {'FROZEN_AT':<20} {'DETAILS'}")
    print("-" * 64)
    for r in active:
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.frozen_at))
        print(f"{r.pid:<8} {r.status:<16} {r.policy:<10} {ts_str:<20} upper={r.overlay_upperdir or 'none'}")
    print("=" * 64)


def cmd_show(args):
    cfg = load_config(args.config)
    state_file = Path(cfg.response.control_dir).parent / "state.json"
    state_mgr = StateManager(state_file)

    if args.pid not in state_mgr.records:
        # Also check pending decision control file
        ctrl_file = Path(cfg.response.control_dir) / f"decision_pid{args.pid}.json"
        if ctrl_file.exists():
            print(json.dumps(json.loads(ctrl_file.read_text()), indent=2))
            return
        print(f"PID {args.pid} is not present in AdaptShield containment records.")
        return

    record = state_mgr.records[args.pid]
    print(json.dumps(asdict(record), indent=2))


def cmd_release(args):
    cfg = load_config(args.config)
    ctrl_dir = cfg.response.control_dir
    state_file = Path(ctrl_dir).parent / "state.json"
    state_mgr = StateManager(state_file)

    # Thaw per-PID cgroup
    unfreeze_pid(args.pid)
    # Clear decision file
    clear_manual_decision(ctrl_dir, args.pid)
    # Record state resolution
    state_mgr.record_resolution(args.pid, "release")

    print(f"Successfully released and thawed PID {args.pid} (marked false positive).")


def cmd_confirm(args):
    cfg = load_config(args.config)
    ctrl_dir = cfg.response.control_dir
    state_file = Path(ctrl_dir).parent / "state.json"
    state_mgr = StateManager(state_file)

    record = state_mgr.records.get(args.pid)
    upper = record.overlay_upperdir if record and record.overlay_upperdir else os.path.join(cfg.response.quarantine_dir, "upper")
    work = record.overlay_workdir if record and record.overlay_workdir else os.path.join(cfg.response.quarantine_dir, "work")

    result = resolve_manual_decision(
        pid=args.pid,
        decision="confirm",
        upperdir=upper,
        workdir=work,
        quarantine_root=cfg.response.quarantine_dir,
        control_dir=ctrl_dir,
        rollback_available=True,
    )
    state_mgr.record_resolution(args.pid, "confirm")

    print(f"Confirmed ransomware for PID {args.pid}.")
    print(f"  Quarantine:  {result.quarantine_path} ({result.quarantined_files} files preserved)")
    print(f"  Rollback:    {'Completed' if result.rolled_back else 'Unavailable'}")
    print(f"  Process:     Terminated")


# -----------------------------------------------------------------------------
# 5. Mode
# -----------------------------------------------------------------------------

def cmd_mode(args):
    cfg = load_config(args.config)
    if not args.target_mode:
        print(f"Current configured mode: {cfg.mode}")
        return

    target = args.target_mode.lower()
    if target not in ("monitor", "protect", "learn"):
        print(f"Invalid mode '{target}'. Must be monitor, protect, or learn.")
        return

    # If config file exists, update it
    conf_path = Path(args.config or "/etc/adaptshield/config.yaml")
    if conf_path.exists():
        try:
            data = yaml.safe_load(conf_path.read_text()) or {}
            data["mode"] = target
            conf_path.write_text(yaml.safe_dump(data, sort_keys=False))
            print(f"Updated {conf_path}: mode set to '{target}'.")
        except Exception as e:
            print(f"Could not update config file: {e}")
    else:
        print(f"Operating mode switched to '{target}' (runtime memory).")


# -----------------------------------------------------------------------------
# 6. Config: check, show, edit
# -----------------------------------------------------------------------------

def cmd_config(args):
    conf_path = Path(args.config or "/etc/adaptshield/config.yaml")
    if args.action == "show":
        if conf_path.exists():
            print(conf_path.read_text())
        else:
            print(f"No configuration file found at {conf_path}. Showing default template:")
            cfg = AdaptShieldConfig()
            print(yaml.safe_dump(cfg.model_dump(), sort_keys=False))
    elif args.action == "check":
        try:
            cfg = load_config(str(conf_path) if conf_path.exists() else None)
            print(f"Configuration is valid (schema version 1.0.0). Mode: {cfg.mode}, Policy: {cfg.response.policy}.")
        except Exception as e:
            print(f"Configuration validation FAILED: {e}")
            sys.exit(1)
    elif args.action == "edit":
        editor = os.environ.get("EDITOR", "nano" if sys.platform != "win32" else "notepad")
        if not conf_path.exists():
            print(f"Config file {conf_path} does not exist; creating with defaults...")
            conf_path.parent.mkdir(parents=True, exist_ok=True)
            conf_path.write_text(yaml.safe_dump(AdaptShieldConfig().model_dump(), sort_keys=False))
        subprocess.run([editor, str(conf_path)])


# -----------------------------------------------------------------------------
# 7. Allowlist: list, add, remove
# -----------------------------------------------------------------------------

def cmd_allowlist(args):
    conf_path = Path(args.config or "/etc/adaptshield/config.yaml")
    cfg = load_config(str(conf_path) if conf_path.exists() else None)

    if args.action == "list":
        print("=" * 64)
        print(" AdaptShield Protection Allowlists")
        print("=" * 64)
        print(f"Process Names: {', '.join(cfg.allowlist.process_names)}")
        print(f"Executables:   {', '.join(cfg.allowlist.exe_paths)}")
        print(f"Users:         {', '.join(cfg.allowlist.users)}")
        print("=" * 64)
        return

    if not conf_path.exists():
        print(f"Config file {conf_path} not found. Cannot modify allowlist.")
        return

    data = yaml.safe_load(conf_path.read_text()) or {}
    allow = data.setdefault("allowlist", {})
    names = allow.setdefault("process_names", list(cfg.allowlist.process_names))

    if args.action == "add":
        if args.item not in names:
            names.append(args.item)
            conf_path.write_text(yaml.safe_dump(data, sort_keys=False))
            print(f"Added '{args.item}' to allowlisted process names.")
        else:
            print(f"'{args.item}' is already allowlisted.")
    elif args.action == "remove":
        if args.item in names:
            names.remove(args.item)
            conf_path.write_text(yaml.safe_dump(data, sort_keys=False))
            print(f"Removed '{args.item}' from allowlisted process names.")
        else:
            print(f"'{args.item}' was not found in allowlist.")


# -----------------------------------------------------------------------------
# 8. Model: list, info, set, reload, rollback
# -----------------------------------------------------------------------------

def cmd_model(args):
    cfg = load_config(args.config)
    reg_dir = cfg.classifier.registry_dir

    if not Path(reg_dir).exists():
        print(f"Model registry directory {reg_dir} does not exist.")
        return

    reg = ModelRegistry(reg_dir)

    if args.action == "list":
        models = reg.list_models()
        print("=" * 64)
        print(f"{'NAME':<20} {'TYPE':<15} {'SOURCE':<10} {'ACTIVE':<8} {'SHA256'[:12]}")
        print("-" * 64)
        for m in models:
            act_str = "ACTIVE" if m.get("active") else "NO"
            print(f"{m.get('name', 'N/A'):<20} {m.get('classifier_type', 'N/A'):<15} {m.get('data_source', 'N/A'):<10} {act_str:<8} {m.get('sha256', '')[:10]}")
        print("=" * 64)

    elif args.action == "info":
        name = args.target
        if not name:
            _clf, manifest = reg.get_active_model()
            print(json.dumps(manifest, indent=2))
        else:
            found = [m for m in reg.list_models() if m.get("name") == name]
            if found:
                print(json.dumps(found[0], indent=2))
            else:
                print(f"Model '{name}' not found in registry.")

    elif args.action == "set":
        try:
            reg.activate_model(args.target)
            print(f"Activated model '{args.target}' in registry.")
        except Exception as e:
            print(f"Could not activate model '{args.target}': {e}")

    elif args.action == "reload":
        print("Signaling agent daemon to reload active model...")
        # If running on POSIX, find agent PID and send SIGHUP
        pid_file = Path("/var/run/adaptshield/adaptshield.pid")
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 1)  # SIGHUP
                print(f"Sent SIGHUP to agent process PID {pid}.")
            except Exception as e:
                print(f"Could not signal agent daemon: {e}")
        else:
            print("Agent PID file not found. Model registry updated on disk.")

    elif args.action == "rollback":
        models = reg.list_models()
        inactive = [m["name"] for m in models if not m.get("active")]
        if inactive:
            prev = inactive[0]
            reg.activate_model(prev)
            print(f"Rolled back active model to previous entry: '{prev}'.")
        else:
            print("No previous model found in registry to rollback to.")


# -----------------------------------------------------------------------------
# 9. Train, Evaluate, Simulate
# -----------------------------------------------------------------------------

def cmd_train(args):
    print(f"Launching training job (classifier={args.classifier}, data={args.data or 'default splits'})...")
    try:
        from .ml.train import train_classifier
        import pandas as pd
        train_path = args.data or "data/raw/traces_train.csv"
        df = pd.read_csv(train_path)
        clf = train_classifier(args.classifier or "random_forest", df)
        print(f"Successfully trained {args.classifier or 'random_forest'} on {len(df)} rows.")
    except Exception as e:
        print(f"Training failed: {e}")


def cmd_evaluate(args):
    print("Evaluating models against test datasets...")
    try:
        from .ml.evaluate import evaluate_classifier
        import pandas as pd
        test_path = args.data or "data/raw/traces_test.csv"
        df = pd.read_csv(test_path)
        clf = build_classifier("rule_based")
        metrics = evaluate_classifier(clf, df)
        print("Evaluation Results:")
        print(f"  Accuracy:  {metrics.get('accuracy', 0.0):.4f}")
        print(f"  F1 Score:  {metrics.get('f1', 0.0):.4f}")
        print(f"  Precision: {metrics.get('precision', 0.0):.4f}")
        print(f"  Recall:    {metrics.get('recall', 0.0):.4f}")
    except Exception as e:
        print(f"Evaluation failed: {e}")


def cmd_simulate(args):
    target_dir = Path(args.target or tempfile.gettempdir()) / f"adaptshield_sim_{args.sim_type}"
    target_dir.mkdir(parents=True, exist_ok=True)
    print(f"Running safe {args.sim_type} simulation in sandbox: {target_dir}")

    if args.sim_type == "benign":
        # Create standard non-malicious text files with normal write gaps
        for i in range(10):
            p = target_dir / f"doc_{i}.txt"
            p.write_text(f"Benign document content {i}\n" * 10)
            time.sleep(0.01)
        print("Benign simulation finished. Generated 10 standard text files.")
    else:
        # Create mock locked files for demonstration
        for i in range(10):
            p = target_dir / f"doc_{i}.txt.locked"
            p.write_bytes(os.urandom(1024))
        print("Simulated ransomware encryption completed in sandbox.")


# -----------------------------------------------------------------------------
# Main Parser Construction
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="adaptshield",
        description="AdaptShield Autonomous Endpoint Security CLI",
    )
    parser.add_argument("-c", "--config", default=None, help="Path to config YAML")

    sub = parser.add_subparsers(dest="subcommand", required=True)

    # 1. status / doctor / version
    sub.add_parser("version")
    sub.add_parser("status")
    sub.add_parser("doctor")

    # 2. run
    p_run = sub.add_parser("run")
    p_run.add_argument("--dry-run", action="store_true", help="Log actions without containing")

    # 3. alerts
    p_alerts = sub.add_parser("alerts")
    p_alerts.add_argument("--follow", "-f", action="store_true", help="Tail alert log")
    p_alerts.add_argument("--since", default=None, help="Filter alerts (e.g. 1h, 30m)")
    p_alerts.add_argument("--json", action="store_true", help="Output raw JSON records")

    # 4. Containment: list, show, release, confirm
    sub.add_parser("list")
    p_show = sub.add_parser("show")
    p_show.add_argument("pid", type=int, help="Target process PID")
    p_rel = sub.add_parser("release")
    p_rel.add_argument("pid", type=int, help="PID to thaw and mark false-positive")
    p_conf = sub.add_parser("confirm")
    p_conf.add_argument("pid", type=int, help="PID to confirm as ransomware and quarantine")

    # 5. mode
    p_mode = sub.add_parser("mode")
    p_mode.add_argument("target_mode", nargs="?", choices=["monitor", "protect", "learn"])

    # 6. config
    p_cfg = sub.add_parser("config")
    p_cfg.add_argument("action", choices=["check", "show", "edit"])

    # 7. allowlist
    p_al = sub.add_parser("allowlist")
    p_al.add_argument("action", choices=["list", "add", "remove"])
    p_al.add_argument("item", nargs="?", help="Process name to add or remove")

    # 8. model
    p_mod = sub.add_parser("model")
    p_mod.add_argument("action", choices=["list", "info", "set", "reload", "rollback"])
    p_mod.add_argument("target", nargs="?", help="Target model name or path")

    # 9. train / evaluate / simulate
    p_tr = sub.add_parser("train")
    p_tr.add_argument("--data", default=None)
    p_tr.add_argument("--classifier", choices=["rule_based", "random_forest", "xgboost"])

    p_ev = sub.add_parser("evaluate")
    p_ev.add_argument("--data", default=None)
    p_ev.add_argument("--model", default=None)

    p_sim = sub.add_parser("simulate")
    p_sim.add_argument("sim_type", choices=["benign", "ransomware"])
    p_sim.add_argument("--target", default=None)

    args = parser.parse_args()

    dispatch = {
        "version": cmd_version,
        "status": cmd_status,
        "doctor": cmd_doctor,
        "run": cmd_run,
        "alerts": cmd_alerts,
        "list": cmd_list,
        "show": cmd_show,
        "release": cmd_release,
        "confirm": cmd_confirm,
        "mode": cmd_mode,
        "config": cmd_config,
        "allowlist": cmd_allowlist,
        "model": cmd_model,
        "train": cmd_train,
        "evaluate": cmd_evaluate,
        "simulate": cmd_simulate,
    }

    fn = dispatch.get(args.subcommand)
    if fn:
        fn(args)


if __name__ == "__main__":
    main()
