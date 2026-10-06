"""
Structured logging module for AdaptShield.
Provides console logging, rotating file logging, and optional journald integration.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOGGER_INITIALIZED = False


def setup_logging(
    level: str = "INFO",
    log_file: str | None = "/var/log/adaptshield/adaptshield.log",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    use_journald: bool = False,
) -> logging.Logger:
    """Configures structured logging for the AdaptShield daemon/agent."""
    global _LOGGER_INITIALIZED

    root_logger = logging.getLogger("adaptshield")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    root_logger.handlers.clear()

    # Formatter for standard output and file logs
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 1. Console Stream Handler
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    # 2. Rotating File Handler (if log_file specified)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except (PermissionError, OSError) as e:
            # Fallback to local log file if system path is not writable
            fallback_dir = Path("results/logs")
            fallback_dir.mkdir(parents=True, exist_ok=True)
            fallback_path = fallback_dir / "adaptshield.log"
            try:
                fallback_handler = RotatingFileHandler(
                    str(fallback_path),
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding="utf-8",
                )
                fallback_handler.setFormatter(formatter)
                root_logger.addHandler(fallback_handler)
                root_logger.warning(
                    "Could not write to %s (%s). Falling back to %s",
                    log_file,
                    e,
                    fallback_path,
                )
            except Exception:
                pass

    # 3. Optional Journald Handler
    if use_journald:
        try:
            from systemd.journal import JournalHandler

            journal_handler = JournalHandler()
            journal_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            root_logger.addHandler(journal_handler)
            root_logger.info("systemd-journald logging attached.")
        except ImportError:
            root_logger.debug("systemd python module not installed; journald handler skipped.")
        except Exception as e:
            root_logger.warning("Could not initialize journald handler: %s", e)

    _LOGGER_INITIALIZED = True
    return root_logger


def get_logger(name: str = "adaptshield") -> logging.Logger:
    """Returns the application logger."""
    global _LOGGER_INITIALIZED
    if not _LOGGER_INITIALIZED:
        setup_logging()
    return logging.getLogger(name)
