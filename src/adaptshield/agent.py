"""
AdaptShield Endpoint Agent Service Entry Point (`adaptshield-agent`).

Full pipeline lifecycle wiring:
  config -> preflight -> cgroups -> protection layers -> classifier selection -> Tier-0 (plus Tier-1) -> detection -> response.
Handles SIGTERM/SIGINT (thaw frozen processes if configured, flush logs, unmount overlays)
and SIGHUP (hot reload config and model without restarting daemon).
"""
from __future__ import annotations

import argparse
import os
import platform
import signal
import sys
from pathlib import Path
from typing import Any

from .config import AdaptShieldConfig, load_config
from .daemon import AdaptShieldDaemon
from .detection.tier1_bridge import is_tier1_available
from .logging.logger import get_logger, setup_logging
from .ml.selector import select_classifier
from .response.containment_manager import ContainmentManager

logger = get_logger("adaptshield.agent")


def run_preflight_checks(config: AdaptShieldConfig) -> dict[str, Any]:
    """
    Executes preflight validation checks for the endpoint environment:
    - Kernel version
    - cgroup v2 and freezer controller support
    - fanotify availability
    - BCC / eBPF support
    - Process privileges (root / CAP_SYS_ADMIN)
    - Model registry and active detector
    """
    results: dict[str, Any] = {
        "platform": sys.platform,
        "os_release": platform.uname().release,
        "is_root": getattr(os, "geteuid", lambda: -1)() == 0,
        "cgroup_v2": False,
        "freezer_available": False,
        "containment_backend": "none",
        "fanotify_available": False,
        "tier1_bcc_available": is_tier1_available(),
        "model_loaded": False,
        "model_name": "unknown",
        "warnings": [],
    }

    # 1. Privileges
    if not results["is_root"] and sys.platform == "linux":
        results["warnings"].append("Not running as root (CAP_SYS_ADMIN required for real containment).")

    # 2. cgroup v2 & freezer check via ContainmentManager authority
    cm = ContainmentManager()
    backend = cm.get_backend()
    results["containment_backend"] = backend
    if cm.is_cgroup_v2():
        results["cgroup_v2"] = True
        # In unified cgroup v2, freezer is a core native capability via per-cgroup cgroup.freeze
        # and does not require delegation via cgroup.controllers
        results["freezer_available"] = True
    else:
        if sys.platform == "linux":
            results["warnings"].append("Unified cgroup v2 not mounted at /sys/fs/cgroup.")
        else:
            # Non-Linux sandbox / dev environment
            results["freezer_available"] = True

    # 3. fanotify check
    if sys.platform == "linux":
        results["fanotify_available"] = Path("/proc/sys/fs/fanotify").exists()
        if not results["fanotify_available"]:
            results["warnings"].append("fanotify kernel subsystem not detected.")

    # 4. Model selection validation
    try:
        clf, meta = select_classifier(config)
        results["model_loaded"] = clf is not None
        results["model_name"] = meta.get("name", "unknown")
        if meta.get("fallback_used"):
            results["warnings"].append(f"Using fallback detector: {meta.get('fallback_reason')}")
    except Exception as e:
        results["warnings"].append(f"Model selection check error: {e}")

    return results


def main():
    parser = argparse.ArgumentParser(
        prog="adaptshield-agent",
        description="AdaptShield Autonomous Endpoint Protection Daemon",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=None,
        help="Path to configuration YAML (default: /etc/adaptshield/config.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without executing real freeze/kill/rollback operations",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    setup_logging(
        level=cfg.logging.level,
        log_file=cfg.logging.file,
        max_bytes=cfg.logging.max_bytes,
        backup_count=cfg.logging.backup_count,
        use_journald=cfg.logging.use_journald,
    )

    logger.info("=" * 60)
    logger.info("AdaptShield Endpoint Agent starting up (v0.2.0)...")
    logger.info("Configured mode: %s (monitor-first: %dh)", cfg.mode, cfg.monitor_first_period_hours)
    logger.info("Watch paths: %s", cfg.watch.paths)
    logger.info("Protected overlay paths: %s", cfg.protect_paths)

    # Run Preflight Checks
    preflight = run_preflight_checks(cfg)
    logger.info(
        "[PREFLIGHT] cgroup_v2=%s, freezer=%s, backend=%s, fanotify=%s, tier1_bcc=%s, detector=%s",
        preflight["cgroup_v2"],
        preflight["freezer_available"],
        preflight.get("containment_backend", "unknown"),
        preflight["fanotify_available"],
        preflight["tier1_bcc_available"],
        preflight["model_name"],
    )
    for warn in preflight["warnings"]:
        logger.warning("[PREFLIGHT WARNING] %s", warn)

    daemon = AdaptShieldDaemon.from_config(cfg, dry_run=args.dry_run)

    # Register Signal Handlers
    def handle_shutdown(signum, frame):
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.info("Received termination signal %s. Initiating graceful shutdown...", sig_name)
        # Thaw processes if policy is none or manual release configured on exit
        thaw = cfg.response.policy in ("none", "manual")
        daemon.stop(thaw_processes=thaw)
        sys.exit(0)

    def handle_reload(signum, frame):
        logger.info("Received SIGHUP. Reloading configuration and model hot...")
        try:
            reloaded_cfg = load_config(args.config)
            daemon.reload_config(reloaded_cfg)
        except Exception as e:
            logger.error("Failed to reload configuration: %s", e)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, handle_reload)

    logger.info("Agent initialization complete. Entering main detection loop...")
    daemon.run_forever()


if __name__ == "__main__":
    main()
