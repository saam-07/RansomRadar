# AdaptShield Implementation Progress

## Done
- Initialized project tracking and repository governance.
- Created `docs/briefs/RULES.md` defining defensive project constraints, execution guidelines, verification standards, and workflow rules.
- Added comprehensive `.gitignore` covering virtual environments, python/node caches, state/log directories, large generated data, zip archives, secrets, and local wrappers.
- Restored baseline prototype assets from archive:
  - `evaluate_model.py` at repository root
  - Bootstrap trace `results/raw/synthetic_traces_bootstrap.csv`
  - Synthetic baseline models `results/processed/xgb_model.joblib` and `results/processed/rf_model.joblib`
- Placed agent brief (`antigravity_prompt_adaptshield_agent.md`) and roadmap prompts (`antigravity_prompts_1_to_17.md`) in `docs/briefs/`.
- Configured local environment with testing dependencies (`pytest`, `pandas`, `scikit-learn`, `xgboost`, `joblib`).
- Executed and validated all 23 existing unit tests across `tests/`.
- Committed unchanged prototype state and created Git tag `v0.1.0-prototype`.

## Verified
- **Unit Test Suite Passing (23/23 tests passed):**
  - `tests/test_classifier.py` (3/3 passed): Rule-based baseline heuristic, scikit-learn random forest joblib serialization round-trip, XGBoost wrapper serialization round-trip.
  - `tests/test_containment_manager.py` (7/7 passed): Userspace overlay upper-directory diff and byte calculations, empty directory diff handling, quarantine copy verification, upper directory wipe on rollback, quarantine preservation, manual decision file writing/reading, PID-specific decision filtering.
  - `tests/test_feature_aggregator.py` (5/5 passed): Shannon entropy computation (0.0 for constant buffers, ~8.0 for uniform random bytes), Tier-1 empty event NaN handling, Tier-1 read/write/rename rate calculations, feature row shape matching `FEATURE_COLUMNS` (11 features).
  - `tests/test_risk_scorer.py` (4/4 passed): Low-risk EWMA scores stay at `RiskLevel.NONE`, sustained high probabilities reach `RiskLevel.CRITICAL`, single transient spikes do not trigger premature containment, independent tracking across distinct PIDs.
  - `tests/test_tier0_scoring.py` (4/4 passed): Inter-event timestamp spacing Gini coefficient (uniform vs bursty), Tier-0 heuristic suspicion scores (benign patterns score low, ransomware patterns score high).

## Not Verified (Requires Linux Kernel / Root Privileges)
- **Fanotify Subsystem (`adaptshield/fanotify_ctypes.py`, `adaptshield/tier0_watcher.py`):**
  - Real-time kernel event intercept via `fanotify_init` / `fanotify_mark` (`FAN_CLASS_NOTIF`, `FAN_OPEN_PERM`, `FAN_CLOSE_WRITE`).
  - Requires Linux kernel >= 5.9 with fanotify enabled and `CAP_SYS_ADMIN` / root.
- **eBPF Tier-1 Kernel Tracing (`adaptshield/tier1_bridge.py`, `ebpf/tier1_trace.bpf.c`):**
  - Kernel kprobe attachment to `sys_enter_write`, `sys_enter_read`, `sys_enter_rename*` via BCC.
  - Requires Linux kernel headers, BCC compiler infrastructure, and root permissions.
- **cgroup v2 Freezer Containment (`adaptshield/containment_manager.py`):**
  - Moving target processes into `/sys/fs/cgroup/` freezer cgroups (`cgroup.freeze`) and process termination (`SIGKILL`).
  - Requires cgroup v2 filesystem mounted with `freezer` controller and root privileges.
- **Real OverlayFS Filesystem Layering:**
  - Live mounting of overlayfs (`mount -t overlay ...`) on ext4/btrfs/xfs.
- *How to verify on Linux VM:* Run `sudo ./setup/verify_all.sh` or execute Phase 1–3 verification commands from `README.md` on an Ubuntu 22.04/24.04 VM.

## Next
- **Prompt 2:** Datasets generation (`feat/datasets` branch) — implement `scripts/make_datasets.py`, train/val/test/hard_test splits, scenario configurations, `DATASET_CARD.md`, and manifest.

---

## Roadmap: Prompts 2 to 17 Status

| Prompt | Topic | Target Branch | Status | Description |
|---|---|---|:---:|---|
| Prompt 2 | Datasets | `feat/datasets` | not started | Build `scripts/make_datasets.py`, generate reproducible trace splits, define scenarios, create dataset card and manifest |
| Prompt 3 | Model Training, Evaluation, Registry | `feat/ml` | not started | Refactor ML pipeline into `ml/`, implement schema contract, build `models/registry/`, train RF/XGB/Tier-0/rule-based models |
| Prompt 4 | Backend Core | `feat/backend-core` | not started | Implement `EventSource` (simulated/replay/live), `ResponseEngine`, pipeline execution, per-PID containment, CLI scenario runner |
| Prompt 5 | Backend API & WebSocket | `feat/api` | not started | FastAPI REST API, SQLite database, WebSocket stream (`/api/stream`), OpenAPI documentation |
| Prompt 6 | Frontend Foundation & Dashboard | `feat/dashboard` | not started | Vite + React + TS UI, Tailwind CSS, live dashboard, process table, risk timeline, alert drawer |
| Prompt 7 | Scenario Runner & Restoration Visual | `feat/scenarios` | not started | Scenario runner page, live file encryption/rollback visualization, side-by-side detector comparison |
| Prompt 8 | Datasets & Models UI | `feat/ml-ui` | not started | Datasets explorer, model training and registry management, interactive 11-feature "Try it" predictor |
| Prompt 9 | Forensics & Guided Demo | `feat/guided-demo` | not started | Forensic investigation drawer, engine settings controls, automated 3-minute guided demo narrative |
| Prompt 10 | Demo Release & Packaging | `feat/demo-release` | not started | Docker Compose orchestration, Makefile automation, CI suite, acceptance criteria audit, `v0.2.0-demo` tag |
| Prompt 11 | Agent Packaging, Config, Logging | `feat/agent-core` | not started | Reorganize into `src/` layout with `pyproject.toml`, YAML config system, structured rotating/journald logging, Tier-0 fallback |
| Prompt 12 | Per-Process Containment & Rails | `feat/agent-containment` | not started | Dedicated per-PID freezer cgroups, process allowlists, false-positive storm panic switch, persistent state recovery |
| Prompt 13 | Protection & Multi-Path Watching | `feat/agent-protection` | not started | Multi-mount fanotify monitoring, automated overlayfs protection manager, non-destructive fallbacks |
| Prompt 14 | Agent Daemon & ML Auto-Selection | `feat/agent-main` | not started | Agent main loop, signal handling (`SIGTERM`/`SIGHUP`), operating modes (`monitor`/`protect`/`learn`), synthetic guard |
| Prompt 15 | AdaptShield Agent CLI | `feat/agent-cli` | not started | Unified `adaptshield` command-line utility (`status`, `doctor`, `run`, `alerts`, `release`, `confirm`, `simulate`) |
| Prompt 16 | Installer & Systemd Service | `feat/agent-installer` | not started | Standalone `install.sh` / `uninstall.sh`, systemd service unit, preflight hardware/kernel verification |
| Prompt 17 | Agent Release & Verification | `feat/agent-release` | not started | Comprehensive test suite, documentation rewrite, acceptance criteria audit, `v0.2.0` agent release tag |
