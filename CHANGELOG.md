# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-10-06

### Added
- **Autonomous Linux Agent:** `src/adaptshield/agent.py` and `daemon.py` with zero required CLI arguments, automated preflight diagnostics, and graceful signal handling (`SIGTERM`, `SIGINT`, `SIGHUP`).
- **Standardized Packaging & Layout:** Standard `src/` layout with `pyproject.toml` exposing entry points `adaptshield` and `adaptshield-agent`.
- **YAML Configuration System:** Dynamic configuration (`/etc/adaptshield/config.yaml`) with documented defaults and Pydantic validation across watch paths, policies, thresholds, allowlists, and logging.
- **Dedicated Per-PID cgroups v2 Containment:** Replaced single shared cgroups with dedicated `/sys/fs/cgroup/adaptshield/proc_<pid>/` cgroups, enabling independent containment and per-PID unfreezing.
- **Immunity Rails & Panic Switch:** Hardcoded immunity for PID 1, systemd, sshd, and database engines; false-positive storm panic switch automatically drops to `monitor` mode if >5 PIDs trigger CRITICAL within 30s.
- **Automated OverlayFS Protection Manager:** Multi-path overlayfs mounting with persistent reboot manifest (`overlay_manifest.json`) and non-destructive quarantine fallback.
- **Operating Modes & Grace Period:** Built-in `monitor`, `protect`, and `learn` modes with a configurable 24-hour monitor-first grace period.
- **ML Seam & Synthetic Guard:** Canonical 11-feature contract (`ml/schema.py`), classifier plugin interface, zero-crash fallback to `RuleBasedClassifier`, and guard preventing synthetic-trained models from unattended containment without explicit opt-in.
- **Flight Telemetry Flywheel:** Continuous feature streaming to `/var/lib/adaptshield/telemetry/` with 50 MB rotation caps.
- **Explainable Forensic Alerts:** Per-alert decision explanations with rule triggers and tree feature contributions.
- **Unified `adaptshield` CLI:** 16 subcommands (`status`, `doctor`, `run`, `alerts`, `list`, `show`, `release`, `confirm`, `mode`, `config`, `allowlist`, `model`, `train`, `evaluate`, `simulate`, `version`).
- **Production Installer & systemd Unit:** Idempotent `install.sh` with preflight report, `uninstall.sh` with `--purge` protection, `packaging/systemd/adaptshield.service`, and Debian `.deb` package builder.
- **Comprehensive Documentation:** `docs/architecture.md`, `docs/ml_integration.md`, `docs/threat_model.md`, `docs/limitations.md`, `docs/installer_verification.md`, and `docs/agent_acceptance_report.md`.

---

## [0.2.0-demo] - 2026-10-06

### Added
- **FastAPI Backend:** REST API (`/api/status`, `/api/scenarios`, `/api/models`, `/api/alerts`) and batched WebSocket stream (`/api/stream`).
- **React + Vite Dashboard:** Live process table, risk timeline charts, forensic evidence drawer, and persistent simulated demo badge.
- **Scenario Runner:** Interactive execution of 8 benchmark scenarios with virtual filesystem grid showing encryption and rollback in real time.
- **Detector Comparison:** Side-by-side execution across Rule-Based Heuristic, Random Forest, and XGBoost detectors.
- **Datasets & Models UI:** Dataset explorer, confusion matrices, ROC/PR curves, and 11-feature interactive "Try it" predictor.
- **Guided Demo Mode:** Automated 3-minute scripted demonstration walkthrough.
- **Docker Compose:** Containerized demonstration orchestration.

---

## [0.1.0-prototype] - 2026-10-06

### Added
- Initial proof-of-concept prototype with fanotify and eBPF scripts.
- Benchmark trace generation and experimental evaluation code.
