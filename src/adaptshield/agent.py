"""
AdaptShield Endpoint Agent entry point.
This is the service entry point called by systemd (`adaptshield-agent`).
Takes NO required arguments; everything is driven by /etc/adaptshield/config.yaml.
"""
from __future__ import annotations

import argparse
import sys

from .config import load_config
from .daemon import AdaptShieldDaemon
from .logging.logger import setup_logging, get_logger

logger = get_logger("adaptshield.agent")


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

    logger.info("Starting AdaptShield Endpoint Agent...")
    daemon = AdaptShieldDaemon.from_config(cfg, dry_run=args.dry_run)
    daemon.run_forever()


if __name__ == "__main__":
    main()
