# AdaptShield Implementation Progress

## Done
- **Prompt 1 (Setup & Rules):**
  - Initialized project tracking and repository governance.
  - Created `docs/briefs/RULES.md` defining defensive project constraints, execution guidelines, verification standards, and workflow rules.
  - Added comprehensive `.gitignore` covering virtual environments, python/node caches, state/log directories, large generated data, zip archives, secrets, and local wrappers.
  - Restored baseline prototype assets (`evaluate_model.py`, bootstrap trace `results/raw/synthetic_traces_bootstrap.csv`, baseline models `xgb_model.joblib` and `rf_model.joblib`).
  - Placed agent brief (`antigravity_prompt_adaptshield_agent.md`) and roadmap prompts (`antigravity_prompts_1_to_17.md`) in `docs/briefs/`.
  - Executed all 23 baseline unit tests across `tests/`.
  - Committed unchanged prototype state and created Git tag `v0.1.0-prototype`.
- **Prompt 2 (Datasets):**
  - Evaluated existing `dataset/make_synthetic_bootstrap.py` for separability: confirmed trivial separability (100% accuracy on single thresholds for `t1_mean_entropy`, `rename_rate`, `t1_rename_rate`, and `concentration_gini`).
  - Built `scripts/make_datasets.py` supporting reproducible fixed seeds, per-run parameter jitter, correlated feature generation, realistic class overlap (backup vs ransomware, oltp vs ransomware), and unescalated Tier-1 NaN sentinels.
  - Created `Makefile` with `make data` and `make test` targets.
  - Generated reproducible splits: `data/raw/traces_train.csv` (3,600 rows / 240 runs), `traces_val.csv` (1,200 rows / 80 runs), `traces_test.csv` (1,200 rows / 80 runs), and `traces_hard_test.csv` (1,800 rows / 120 runs).
  - Generated 8 benchmark scenario definitions in `data/scenarios/*.json` (`normal_workday`, `nightly_backup`, `oltp_database`, `fast_ransomware`, `slow_and_low_ransomware`, `intermittent_ransomware`, `partial_encryption`, `mixed_chaos`).
  - Generated `data/manifest.json` and `data/DATASET_CARD.md`.
  - Implemented unit tests in `tests/test_datasets.py` validating schema conformity, zero run_id leakage, reproducibility, non-trivial separability, manifest count synchronization, and held-out scenario isolation.
- **Prompt 3 (Model Training, Evaluation, Registry):**
  - Refactored training and evaluation logic into modular, importable functions under `adaptshield.ml/` and root alias `ml/`.
  - Defined feature schema contract in `adaptshield/ml/schema.py` (`SCHEMA_VERSION = "1.0.0"`, validation, metadata stripping, NaN sentinel semantics).
  - Built `ModelRegistry` in `adaptshield/ml/registry.py` managing `models/registry/`, enforcing compatibility validation and active model state.
  - Built `scripts/train_all.py` (and `make train`) training `rule_based`, `rf_tier0_ablation`, `random_forest`, and `xgboost` (active model).
  - Registered legacy synthetic bootstrap models (`legacy_synthetic_xgb`, `legacy_synthetic_rf`) flagged as `synthetic_bootstrap_legacy`.
  - Saved comprehensive metrics JSON (`models/registry/all_models_metrics.json`) including ROC/PR curve coordinates, per-scenario breakdowns, and EWMA risk-scorer replays.
  - Documented findings in `docs/ml_report.md`.
  - Implemented unit test suite in `tests/test_ml.py` verifying schema validation, column mismatch rejection, training reproducibility, and hard test set degradation.
- **Prompt 4 (Backend Core):**
  - Implemented `EventSource` interface in `backend/app/core/sources.py` with `SimulatedSource`, `ReplaySource`, and `LiveAgentSource` (stub marked unverified).
  - Implemented `ResponseEngine` interface in `backend/app/core/response.py` with `SimulatedResponse` (virtual filesystem, damage tracking, rollback, per-process state isolation, policies `immediate`/`manual`/`none`, auto-resolve timeout) and `RealResponse` (wrapping `containment_manager`, feature-flagged).
  - Implemented `SafetyRails` in `backend/app/core/safety.py` enforcing immunity for PID 1, kernel threads, system daemons, allowlisted processes, rate limits, and false-positive storm panic switch.
  - Implemented forensic alert attribution in `backend/app/core/explain.py` for tree models and rule-based heuristics.
  - Implemented in-process `EventBus` in `backend/app/core/bus.py` with history buffer and subscriber routing.
  - Built `DetectionPipeline` in `backend/app/core/pipeline.py` connecting all stages with independent per-process state.
  - Built standalone CLI scenario runner `backend/app/run_scenario.py`.
- **Prompt 5 (Backend API, WebSocket, Database):**
  - Built FastAPI application layer in `backend/app/` with SQLite database and versioned migrations (`backend/app/db/`).
  - Implemented all Section 6 endpoints: status and control (`/api/status`, `/api/control`, `/api/health`), processes (`/api/processes`), alerts with forensic evidence (`/api/alerts`, `/api/alerts/{id}`), release and confirm containment (`/api/containment/release`, `/api/containment/confirm`), scenario definitions and background execution (`/api/scenarios`, `/api/scenarios/run`, `/api/scenarios/stop`, `/api/scenarios/runs`), datasets overview and sampling (`/api/datasets`, `/api/datasets/{split}/sample`, `/api/datasets/{split}/stats`, `/api/datasets/generate`), and model registry operations (`/api/models`, `/api/models/{name}/evaluation`, `/api/models/activate`, `/api/models/train`, `/api/models/training/{id}`, `/api/models/predict`).
  - Enforced schema compatibility check on model activation (rejects incompatible models with HTTP 400).
  - Implemented WebSocket streaming at `/api/stream` with batched message delivery (`window_scored`, `process_update`, `escalation`, `alert`, `containment`, `file_damage`, `rollback`, `scenario_state`).
  - Added configuration via `backend/config.yaml` and environment variables.
  - Implemented auto-seeding of demo data on first start if DB is empty.
  - Enforced provenance tagging (`simulated: true` on all simulated responses, `data_source: synthetic` on all model responses).
  - Wrote comprehensive API guide with curl examples in `docs/api.md`.
  - Implemented test suite in `tests/test_api.py` (14/14 tests passing).

## Verified
- **Full Repository Test Suite Passing (58/58 tests passed):**
  - `tests/test_api.py` (14/14 passed):
    - `test_health_endpoint`: validates health response and `simulated: true`.
    - `test_status_endpoint`: validates mode, policy, active detector, and data source.
    - `test_control_endpoint`: verifies policy and mode switching.
    - `test_processes_endpoint`: verifies process table inspection.
    - `test_alerts_endpoint_and_detail`: verifies alert listing and forensic evidence payload.
    - `test_containment_release_and_confirm`: verifies manual operator containment overrides.
    - `test_scenarios_listing`: validates all 8 scenarios available.
    - `test_scenario_run_and_history`: starts background scenario, records run, and verifies details.
    - `test_datasets_overview_and_samples`: validates dataset manifests, row counts, and sampling.
    - `test_models_listing_and_evaluation`: verifies registry listing and detailed evaluation report.
    - `test_model_predict`: verifies feature inference, probabilities, and tree attribution explanation.
    - `test_model_activation_compatibility_check`: proves activation works for valid models and strictly rejects incompatible models with HTTP 400.
    - `test_training_job_lifecycle`: validates background training job queue and status polling.
    - `test_websocket_stream`: verifies WebSocket connection acknowledgment and ping/pong.
  - `tests/test_backend_core.py` (7/7 passed)
  - `tests/test_ml.py` (6/6 passed)
  - `tests/test_datasets.py` (8/8 passed)
  - `tests/test_classifier.py` (3/3 passed)
  - `tests/test_containment_manager.py` (7/7 passed)
  - `tests/test_feature_aggregator.py` (5/5 passed)
  - `tests/test_risk_scorer.py` (4/4 passed)
- **Prompt 6 (Frontend Foundation & Live Dashboard):**
  - Initialized `frontend/` with React 18, TypeScript, Vite 6, Tailwind CSS, Recharts, and TanStack React Query.
  - Built dark mode SOC theme layout with sticky `Navbar` displaying a prominent, persistent `SIMULATED DEMO DATA` badge, operating mode, policy selector, active model with synthetic data origin tag, and WebSocket stream status pill.
  - Implemented responsive `Sidebar` navigation with active route to `Live Dashboard` and clean stub placeholders for upcoming features (`Scenario Runner`, `Detector Comparison`, `Datasets Explorer`, `Models & Training`, `Alerts & Forensics`, `System Settings`).
  - Built typed API client (`frontend/src/api/client.ts`) and auto-reconnecting WebSocket hook (`frontend/src/hooks/useWebSocket.ts`) with heartbeat ping/pong and batched event handling.
  - Implemented Live Dashboard components:
    - `KpiCards`: Monitored Processes, Active Threat Alerts, Contained PIDs, Files Protected/Restored.
    - `RiskTimelineChart`: Recharts EWMA risk and raw probability timeline with threshold reference lines at 0.3 (Elevated), 0.6 (Suspicious), and 0.85 (Critical Containment).
    - `ProcessTable`: Real-time monitored processes table with colored EWMA progress bars, risk chips (`NORMAL`/`ELEVATED`/`CRITICAL`), status chips (`normal`/`monitored`/`frozen`/`quarantined`/`killed`), and interactive manual `Release`/`Confirm` controls.
    - `AlertFeed`: Forensic alert feed showing real-time containment triggers.
    - `EvidenceDrawer`: Forensic slide-over investigation drawer displaying tree feature contributions, impact scores, observed window feature vectors, and containment action buttons.
  - Added component test suite in `frontend/src/test/dashboard.test.tsx` (4/4 tests passed via Vitest).
  - Built production bundle (`npm run build` -> `dist/`) without TypeScript warnings or errors.
  - Captured live dashboard screenshot preview in `docs/demo/dashboard_live.png`.

## Verified
- **Frontend Test Suite Passing (4/4 tests passed via Vitest):**
  - `Navbar Component`: validates brand, persistent SIMULATED DEMO DATA badge, active model, and live stream pill.
  - `KpiCards Component`: validates metric counts for processes, critical alerts, contained threats, and protected/restored files.
  - `ProcessTable Component`: validates table rendering, risk EWMA scores, status chips, and callback triggers for `Release` and `Confirm`.
  - `EvidenceDrawer Component`: validates attribution narrative, feature contribution breakdown, observed metrics, and drawer closing.
- **Production Build:**
  - `npm --prefix frontend run build`: cleanly bundled with Vite and TypeScript compiler without errors (`dist/index.html`, `dist/assets/`).
- **Live Backend & Frontend Integration:**
  - Started backend at `http://127.0.0.1:8000` and frontend at `http://127.0.0.1:3000`.
  - Triggered `fast_ransomware` scenario via API (`POST /api/scenarios/run`): completed in 5.4s, contained attacker PID 4099 at window 4 (8.0s), rolled back and restored 55 files, intact 300 files.
  - Saved live dashboard preview screenshot to `docs/demo/dashboard_live.png`.
- **Backend & ML Test Suites Passing (58/58 tests passed):**
  - `tests/test_api.py` (14/14 passed)
  - `tests/test_backend_core.py` (7/7 passed)
  - `tests/test_ml.py` (6/6 passed)
  - `tests/test_datasets.py` (8/8 passed)
  - `tests/test_classifier.py` (3/3 passed)
  - `tests/test_containment_manager.py` (7/7 passed)
  - `tests/test_feature_aggregator.py` (5/5 passed)
  - `tests/test_risk_scorer.py` (4/4 passed)
  - `tests/test_tier0_scoring.py` (4/4 passed)

## Not Verified (Requires Linux Kernel / Root Privileges)
- **Real Containment Execution (`RealResponse`):**
  - `RealResponse` wraps real cgroup freezer and overlay unmount commands. Verified in userspace via `SimulatedResponse`; real execution requires an Ubuntu VM with root.
- **Live Agent Telemetry Stream (`LiveAgentSource`):**
  - Requires live agent running on Linux writing to `/var/log/adaptshield/alert.jsonl`.

- **Prompt 7 (Scenario Runner, Restoration Visualizer, Detector Comparison):**
  - Built `ScenarioRunnerPage` (`frontend/src/pages/ScenarioRunnerPage.tsx`) with cards for all 8 benchmark scenarios (`fast_ransomware`, `slow_and_low_ransomware`, `intermittent_ransomware`, `partial_encryption`, `mixed_chaos`, `normal_workday`, `nightly_backup`, `oltp_database`).
  - Implemented interactive scenario execution toolbar: speed multiplier (1x, 5x, 20x), deterministic seed, detector selector (`xgboost`, `random_forest`, `rule_based`), and containment policy selector (`immediate`, `manual`, `none`).
  - Added Run / Pause / Stop / Reset controls with real-time feedback.
  - Implemented `FilesystemGrid` (`frontend/src/components/scenarios/FilesystemGrid.tsx`): 60-file interactive visualizer showing intact, encrypted (`.locked`), cgroup freezer containment (`OVERLAY FROZEN`), and restored (`.restored` emerald checkmark) states.
  - Built `ScenarioReportModal` (`frontend/src/components/scenarios/ScenarioReportModal.tsx`): post-run execution report showing time-to-detect, files compromised vs preserved, rollback latency, false alarms, and export buttons for JSON and PDF/print.
  - Built `DetectorComparisonPage` (`frontend/src/pages/DetectorComparisonPage.tsx`): side-by-side benchmark comparing Rule-based, Random Forest, and XGBoost with identical seed, Recharts latency and damage charts, and comparative metrics table.
  - Updated backend with `POST /api/scenarios/compare`, `GET /api/scenarios/filesystem`, and `POST /api/scenarios/reset`.
  - Added multi-attacker independent containment tracking in `ScenarioRunnerPage` for `mixed_chaos`.
  - Component tests implemented in `frontend/src/test/scenarios.test.tsx` (6/6 tests passing, 10/10 total frontend tests passing).
  - Playwright E2E smoke test implemented in `frontend/e2e/scenario_smoke.spec.ts` asserting containment, and generating demo screenshots in `docs/demo/filesystem_rollback.png` and `docs/demo/detector_comparison.png`.

## Verified
- **Frontend Test Suite Passing (10/10 tests passed via Vitest):**
  - `src/test/dashboard.test.tsx` (4/4 passed)
  - `src/test/scenarios.test.tsx` (6/6 passed)
  - `src/test/ml_ui.test.tsx` (4/4 passed)
  - `src/test/forensics_and_settings.test.tsx` (5/5 passed)
- **Playwright E2E Smoke Test Passing (1/1 test passed):**
  - `frontend/e2e/scenario_smoke.spec.ts`: loads application, navigates to Scenario Runner, triggers `Fast Ransomware Outbreak`, asserts containment (`OVERLAY FROZEN` / `Locked` / `Restored`), captures `docs/demo/filesystem_rollback.png`, navigates to Detector Comparison, executes side-by-side benchmark, asserts comparative table, and captures `docs/demo/detector_comparison.png`.
- **UI Screenshots Verified:**
  - `docs/demo/datasets_explorer.png`: Datasets explorer with train/val/test/hard_test split cards, class balance breakdown, feature schema specification, and rendered Dataset Card.
  - `docs/demo/models_studio.png`: Model registry table with active status, evaluation curves, hard test degradation alert, and interactive 11-feature "Try it" predictor with presets.
  - `docs/demo/alerts_forensics.png`: Alerts log with risk levels, EWMA scores, and forensic evidence drawer displaying 11-feature snapshot and SHAP factor attribution.
  - `docs/demo/settings_rails.png`: System settings page with EWMA alpha tuning, risk thresholds (0.3/0.6/0.85), allowlist editor, and demo baseline reset.
  - `docs/demo/guided_demo.png`: Interactive 3-minute story mode modal with 5-step progress, narrative talking points, and automated action triggers.
- **Prompt 10 (Demo Release & Packaging):**
  - Configured rootless multi-service container orchestration with `Dockerfile.backend`, `Dockerfile.frontend`, `frontend/nginx.conf`, and `docker-compose.yml`.
  - Added `.env.example` defining environment variable overrides (`PORT`, `VITE_API_URL`, etc.).
  - Added Makefile automation targets: `help`, `data`, `train`, `test-backend`, `test-frontend`, `test`, `demo`, `docker-up`, `docker-down`, `clean`.
  - Added GitHub Actions CI pipeline `.github/workflows/ci.yml` verifying linting, backend pytest, frontend vitest, and typecheck.
  - Authored comprehensive architectural specification `docs/architecture.md` with Mermaid pipeline and state diagrams.
  - Authored honest evasion and limitations report `docs/limitations.md`.
  - Authored Section 10 Acceptance Criteria Audit report `docs/acceptance_report.md` (16 PASS, 2 NOT VERIFIED due to Linux sandbox constraints).
  - Updated `README.md` with quickstart guides, architecture, limitations, and verification instructions.
- **Prompt 11 (Package layout, config, logging):**
  - Moved package to standard `src/adaptshield/` layout with `pyproject.toml` and console entry points (`adaptshield`, `adaptshield-agent`).
  - Implemented `src/adaptshield/config.py` with Pydantic validation and documented defaults. Created `packaging/config.default.yaml`.
  - Implemented structured logging in `src/adaptshield/logging/logger.py` with rotating file handler and journald support.
  - Replaced bare `print()` in `AlertLogger` with structured logging and file rotation.
  - Made `AdaptShieldDaemon` take NO required CLI arguments, driving configuration from defaults and YAML files.
  - Made Tier-1/eBPF optional with automatic runtime graceful degradation to Tier-0-only mode when BCC or kernel headers are missing.
  - Added CLI utility (`adaptshield version`, `adaptshield status`, `adaptshield doctor`).
  - Added unit test suites `tests/test_agent_config.py` and `tests/test_agent_tier0_fallback.py`.
- **Prompt 12 (Per-Process Containment, Safety Rails, State Recovery):**
  - Replaced the single shared freezer cgroup with dedicated per-PID cgroups (`/sys/fs/cgroup/adaptshield/pid_<pid>`) in `src/adaptshield/response/containment_manager.py`.
  - Added independent per-PID containment and release (regression tested: containing two PIDs and releasing one keeps the other frozen).
  - Implemented `SafetyRails` in `src/adaptshield/response/safety.py`: PID 1 immunity, kernel thread immunity (`/proc/<pid>/cmdline` check), agent self/parent/children immunity, system critical process protection (`systemd*`, `sshd`, `dbus`, `login`, etc.), allowlist configuration (process names, executable paths, users), rate limiting (max 10 containments/min), and false-positive storm panic switch (automatically trips to `monitor` mode if >5 containments within 30s).
  - Implemented `StateManager` in `src/adaptshield/state.py`: atomic JSON state persistence (`/var/run/adaptshield/state.json`), startup crash recovery, dead-process cgroup cleanup, and automatic resolution timeout for operator decisions under manual policy.
  - Implemented `dry_run` containment mode in `daemon.py` and `containment_manager.py`.
  - Added comprehensive test suite `tests/test_agent_containment.py` (6 tests).
- **Prompt 13 (Overlay Protection and Multi-Path Watching):**
  - Upgraded fanotify watching to multi-path (`Fanotify` and `Tier0Watcher`), supporting lists of watched paths and configurable excludes with automatic self-exclusion (agent PID excluded).
  - Built `ProtectionManager` in `src/adaptshield/response/protection.py`: creates, mounts, and unmounts dedicated overlayfs layers for each path in `protect_paths`, saves persistent manifest, and remounts across reboots.
  - Implemented non-destructive fallback: when overlayfs cannot be mounted (unsupported filesystem, unprivileged environment, or conflict), AdaptShield logs the reason, gracefully engages `fallback_quarantine_only` (quarantine-copy-on-detect + freeze/kill), and explicitly reports `"rollback unavailable"` in status.
  - Documented kernel and filesystem limitations honestly in `docs/filesystem_limitations.md`.
  - Added unit test suite `tests/test_agent_protection.py` (7 tests) using temporary directories and loopback mocks without touching real user data.
- **Prompt 14 (Agent Main Loop, Operating Modes, ML Auto-Selection, Hot Reload):**
  - Integrated agent service main loop in `src/adaptshield/agent.py` with preflight validation (kernel, cgroups v2, freezer, fanotify, BCC, root privileges, detector model), graceful shutdown (`SIGTERM`/`SIGINT`), and atomic hot reload (`SIGHUP`).
  - Implemented runtime operating modes (`monitor`, `protect`, `learn`) and monitor-first grace period (default 24h before auto-switching to protect) in `src/adaptshield/mode.py`.
  - Built detector auto-selection and synthetic guard in `src/adaptshield/ml/selector.py`: enforces feature schema compatibility, guards against synthetic models executing containment in `protect` mode without authorization (`classifier.allow_synthetic: false`), and safely falls back to `RuleBasedClassifier` without crashing.
  - Built size-rotating telemetry writer in `src/adaptshield/telemetry.py` recording feature rows and containment actions under `/var/lib/adaptshield/telemetry/`.
  - Built forensic alert explanations module in `src/adaptshield/ml/explain.py` for heuristic and tree-based alerts.
  - Implemented unit test suite `tests/test_agent_main.py` (6 tests).
- **Prompt 15 (The `adaptshield` Unified CLI):**
  - Built unified CLI utility in `src/adaptshield/cli.py` exposing 16 subcommands: `status`, `doctor`, `run` (`--dry-run`), `alerts` (`--follow`, `--since`, `--json`), `list`, `show <pid>`, `release <pid>`, `confirm <pid>`, `mode [monitor|protect|learn]`, `config [check|show|edit]`, `allowlist [list|add|remove]`, `model [list|info|set|reload|rollback]`, `train`, `evaluate`, `simulate [benign|ransomware]`, `version`.
  - Implemented thorough preflight diagnostic checks in `adaptshield doctor` (OS platform, cgroup v2, freezer controller, fanotify subsystem, BCC/eBPF, root privileges, active model compatibility).
  - Maintained backward compatibility shim in `containment_cli.py` delegating to `adaptshield.cli`.
  - Implemented unit test suite `tests/test_agent_cli.py` (9 tests) verifying CLI parsing, outputs, and subcommands.
- **Backend & ML Test Suites Passing (97/97 tests passed):**
  - All 97 pytest tests passing across `tests/` (58 demo + 11 agent core + 6 containment + 7 protection + 6 agent main loop + 9 CLI tests).
- **Frontend Test Suite Passing (19/19 tests passed):**
  - All 19 vitest tests passing across `frontend/src/test/`.
- **Frontend Production Bundle:**
  - `npm --prefix frontend run build` bundles cleanly with 0 TypeScript/Vite errors.

## Not Verified (Requires Linux Kernel / Root Privileges)
- **Real Containment Execution (`RealResponse`):**
  - `RealResponse` wraps real cgroup freezer and overlay unmount commands. Verified in userspace with mocked filesystem tree and dry-run mode; real cgroup v2 freeze requires an Ubuntu VM with kernel >= 5.9 and root.
- **Live Fanotify & OverlayFS Mounts (`ProtectionManager` / `Tier0Watcher`):**
  - Tested in userspace with temporary directories and mocked loopback mount/unmount functions; real Linux fanotify and overlayfs attachment require `CAP_SYS_ADMIN` on Linux with kernel >= 5.9.
- **Live Agent Telemetry Stream (`LiveAgentSource`):**
  - Requires live agent running on Linux writing to `/var/log/adaptshield/alert.jsonl`.
- **Live Kernel eBPF Kprobe Attachment (`Tier1Tracer`):**
  - Tested graceful fallback to Tier-0-only mode in userspace; real BCC attachment requires Ubuntu VM with kernel >= 5.9 and root.
- **Production Installer on Live Linux Host (`install.sh` / `systemd`):**
  - Tested in userspace with cross-platform pytest suite and mocked filesystem paths; live APT package installation, systemd enablement, and reboot tests require a fresh Ubuntu 22.04/24.04 VM (checklist documented in `docs/installer_verification.md`).

## Next
- **Prompt 17:** Agent Release, Comprehensive Tests, CI, Docs, Acceptance Criteria (`feat/agent-release` branch).

---

## Roadmap: Prompts 2 to 17 Status

| Prompt | Topic | Target Branch | Status | Description |
|---|---|---|:---:|---|
| Prompt 2 | Datasets | `feat/datasets` | **done** | Build `scripts/make_datasets.py`, generate reproducible trace splits, define scenarios, create dataset card and manifest |
| Prompt 3 | Model Training, Evaluation, Registry | `feat/ml` | **done** | Refactor ML pipeline into `ml/`, implement schema contract, build `models/registry/`, train RF/XGB/Tier-0/rule-based models |
| Prompt 4 | Backend Core | `feat/backend-core` | **done** | Implement `EventSource` (simulated/replay/live), `ResponseEngine`, pipeline execution, per-PID containment, CLI scenario runner |
| Prompt 5 | Backend API & WebSocket | `feat/api` | **done** | FastAPI REST API, SQLite database, WebSocket stream (`/api/stream`), OpenAPI documentation |
| Prompt 6 | Frontend Foundation & Dashboard | `feat/dashboard` | **done** | Vite + React + TS UI, Tailwind CSS, live dashboard, process table, risk timeline, alert drawer |
| Prompt 7 | Scenario Runner & Restoration Visual | `feat/scenarios` | **done** | Scenario runner page, live file encryption/rollback visualization, side-by-side detector comparison |
| Prompt 8 | Datasets & Models UI | `feat/ml-ui` | **done** | Datasets explorer, model training and registry management, interactive 11-feature "Try it" predictor |
| Prompt 9 | Forensics & Guided Demo | `feat/guided-demo` | **done** | Forensic investigation drawer, engine settings controls, automated 3-minute guided demo narrative |
| Prompt 10 | Demo Release & Packaging | `feat/demo-release` | **done** | Docker Compose orchestration, Makefile automation, CI suite, acceptance criteria audit, `v0.2.0-demo` tag |
| Prompt 11 | Agent Packaging, Config, Logging | `feat/agent-core` | **done** | Reorganize into `src/` layout with `pyproject.toml`, YAML config system, structured rotating/journald logging, Tier-0 fallback |
| Prompt 12 | Per-Process Containment & Rails | `feat/agent-containment` | **done** | Dedicated per-PID freezer cgroups, process allowlists, false-positive storm panic switch, persistent state recovery |
| Prompt 13 | Protection & Multi-Path Watching | `feat/agent-protection` | **done** | Multi-mount fanotify monitoring, automated overlayfs protection manager, non-destructive fallbacks |
| Prompt 14 | Agent Daemon & ML Auto-Selection | `feat/agent-main` | **done** | Agent main loop, signal handling (`SIGTERM`/`SIGHUP`), operating modes (`monitor`/`protect`/`learn`), synthetic guard |
| Prompt 15 | AdaptShield Agent CLI | `feat/agent-cli` | **done** | Unified `adaptshield` command-line utility (`status`, `doctor`, `run`, `alerts`, `release`, `confirm`, `simulate`) |
| Prompt 16 | Installer & Systemd Service | `feat/agent-installer` | **done** | Standalone `install.sh` / `uninstall.sh`, systemd service unit, preflight hardware/kernel verification, deb builder |
| Prompt 17 | Agent Release & Verification | `feat/agent-release` | not started | Comprehensive test suite, documentation rewrite, acceptance criteria audit, `v0.2.0` agent release tag |





