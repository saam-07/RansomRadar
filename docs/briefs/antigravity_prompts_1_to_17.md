# AdaptShield: 17 Prompts for Antigravity (paste one at a time, in order)

**Before Prompt 1 (one manual step):** unzip `adaptshield_with_model.zip`, open that folder as your Antigravity workspace, create the folder `docs/briefs/`, and put these two files in it:
- `antigravity_prompt_adaptshield_agent.md`
- `antigravity_prompt_adaptshield_fullstack_demo.md`

**How to use:** paste a prompt, let it finish, check the "Before moving on" line, commit, then paste the next one. Prompts 2 to 10 build the demo (no root needed). Prompts 11 to 17 build the real installable agent (needs an Ubuntu VM with root to verify).

---

## Prompt 1: Project setup and rules

```
You are working on AdaptShield, a Linux ransomware detection and containment project. Two briefs are in docs/briefs/: antigravity_prompt_adaptshield_agent.md and antigravity_prompt_adaptshield_fullstack_demo.md. Read both fully. Do NOT implement features yet.

First, create docs/briefs/RULES.md containing exactly these rules, which apply to every later prompt:

PROJECT RULES
- Defensive security project only. Ransomware behavior is simulated with numbers and virtual files, or with the existing safe simulator confined to a throwaway sandbox directory. Never write real encryption code that touches real user files.
- Reuse the existing `adaptshield` package. Import it; do not duplicate detection logic.
- Do only the task in the current prompt. Do not start the next one.
- Start every task with a short plan (files to touch, order, risks), then implement.
- Never claim something works unless you ran it. End every task with: (a) what changed, (b) exact commands you ran and their results, (c) what you could NOT verify and how I can verify it.
- Do not fake metrics, screenshots or results. Every number shown must be computed from real data or models in the repo.
- Synthetic data must always be labeled synthetic (in files, API responses and UI). Synthetic-trained accuracy is never presented as real-world performance.
- Keep docs/PROGRESS.md updated: done / verified / not verified / next.
- Small, reviewable commits with conventional commit messages. Work on a branch named for the task. Do not push to main.
- If something is ambiguous, pick a sensible default, state it, and continue. Ask only if a wrong guess is costly to undo.

Then:
1. Initialize git if needed. Add a sensible .gitignore (.venv, __pycache__, node_modules, state/log dirs, large generated data, secrets).
2. Commit the unchanged prototype and tag it v0.1.0-prototype.
3. Run the existing unit tests (python -m pytest tests/ -v) and report the real results, noting any failures that need root or kernel features.
4. Create docs/PROGRESS.md with sections Done, Verified, Not verified, Next, and a table of Prompts 2 to 17 (all "not started").
5. Reply with the repo state, test results, and a proposed folder layout for the merged project (demo + agent), noting where the two briefs overlap (feature schema, model registry, containment, classifier interface) so shared pieces are built once.

Do not change any source code in this task.
```
**Before moving on:** tag exists, tests ran (failures explained), `PROGRESS.md` and `RULES.md` exist.

---

## Prompt 2: Datasets

```
Read docs/briefs/RULES.md and docs/briefs/antigravity_prompt_adaptshield_fullstack_demo.md (Sections 4 and 5). Create branch feat/datasets. Do ONLY this task: the datasets.

Build scripts/make_datasets.py (and a `make data` target) producing reproducible output with fixed seeds:
- data/raw/traces_train.csv, traces_val.csv, traces_test.csv, traces_hard_test.csv
- data/scenarios/*.json (scenario definitions for the later simulator)
- data/DATASET_CARD.md and data/manifest.json (sha256, row counts, class counts, schema version, generator version)

Requirements:
- Schema: FEATURE_COLUMNS from adaptshield/feature_aggregator.py plus pid, run_id, scenario, label, window_idx, timestamp, source (synthetic | simulated_process | real).
- Classes: benign, backup, oltp, ransomware, with the scenario families and ransomware variants from Section 4.2 of the brief (fast, slow-and-low, intermittent, partial encryption, rename-then-encrypt, delete-original, mimicry).
- Classes MUST overlap realistically (backup vs ransomware, oltp vs fast ransomware). Add per-run parameter jitter, noise, correlated features, and NaN Tier-1 values for never-escalated processes.
- Split by run_id, never by row. Each run_id appears in exactly one split.
- traces_hard_test.csv contains variants NOT present in train or val.
- Support an imbalanced mode (e.g. 99.9% benign) for false-positives-per-hour reporting.
- First check whether the existing dataset/make_synthetic_bootstrap.py is trivially separable (train a quick model; if about 100%, say so) and report before and after.

Tests (pytest): same seed gives same sha256; zero run_id overlap across splits; schema matches FEATURE_COLUMNS; a single-feature threshold does NOT reach near-perfect accuracy; class counts match the manifest.

Finish with the report format from RULES.md. Commit on the branch. Do not start the next prompt's work.
```
**Before moving on:** read the dataset card, check class counts, run `make data` twice and compare hashes.

---

## Prompt 3: Model training, evaluation, registry

```
Read docs/briefs/RULES.md and the fullstack demo brief (the ML parts of Sections 6 and 8). Create branch feat/ml. Do ONLY this task.

1. Refactor train_model.py and evaluate_model.py logic into importable functions under an ml/ module (keep the CLI wrappers working). Do not change classifier behavior in adaptshield/classifier.py unless required; note any change.
2. Define a feature schema module (version string, column list, dtypes, NaN semantics) and validate inputs against it before predict_proba. Drop pid, label and other non-feature columns.
3. Build a model registry at models/registry/ with a manifest.json per model: name, classifier type, feature columns, schema version, data source mix, metrics, seed, git commit, sha256, trained_at, active flag. Loading must reject incompatible models.
4. scripts/train_all.py and `make train`: train and register rule_based (baseline), random_forest, xgboost, and a Tier-0-only random forest (ablation) on data/raw/traces_train.csv; tune on val; report on test ONCE; report hard_test separately.
5. Metrics per model: precision, recall, F1, ROC-AUC, PR-AUC, confusion matrix, ROC and PR curve points, per-class report, per-scenario-family breakdown, feature importance, false positives per hour at the imbalanced ratio, and the EWMA risk-scorer replay (detection rate and mean windows to detect by class, using adaptshield/risk_scorer.py exactly as the daemon does). Save as JSON for the API to serve later.
6. Register the two existing joblib models (results/processed/xgb_model.joblib and rf_model.joblib) with data_source=synthetic, clearly flagged.
7. Write docs/ml_report.md with the experiment design and honest limitations.

Tests: registry rejects mismatched columns; schema validation catches missing columns; training is reproducible with a seed.

Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```
**Before moving on:** metrics should be believable (not 100%), the hard test set should score lower, and the Tier-0-only model should score lower than the full model.

---

## Prompt 4: Backend core (sources, response engine, pipeline)

```
Read docs/briefs/RULES.md and the fullstack demo brief (Sections 2 and 3). Create branch feat/backend-core. Do ONLY this task: the backend core, without the HTTP layer.

Build in backend/app/:
- EventSource interface with SimulatedSource (virtual processes driven by data/scenarios/*.json, seeded, speed 1x/5x/20x), ReplaySource (replays any labeled trace CSV grouped by pid with speed control), and LiveAgentSource (a stub behind a feature flag that reads the real agent's JSONL; clearly marked unverified).
- ResponseEngine interface with SimulatedResponse (virtual filesystem: protected files, per-process damage, files encrypted, bytes at risk, freeze/quarantine/rollback/kill with none/immediate/manual policy semantics plus an auto-resolve timeout and recorded latencies) and RealResponse (a wrapper over adaptshield/containment_manager.py, feature-flagged, off by default).
- Pipeline: feature rows -> active classifier from the registry -> adaptshield RiskScorer -> response engine. Per-process containment must be INDEPENDENT (two attackers at once; releasing one must not thaw the other).
- Safety rails: allowlist, never contain protected process names, rate limit, storm panic switch (drop to monitor).
- Explanations: per-alert feature contributions (SHAP if installable, else tree contributions or permutation importance); for rule_based, the rule that fired.
- An in-process event bus that will later feed the WebSocket.

Tests (pytest): scenario runs are deterministic with a seed; "normal workday" and "nightly backup" produce zero containments with the chosen model; fast ransomware is contained and rolled back; two simultaneous attackers are contained independently; manual policy release/confirm/timeout work; an allowlisted process is never contained.

Provide `python -m backend.app.run_scenario <scenario> --detector xgboost` that prints a result summary so I can verify without a UI.

Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```
**Before moving on:** run the CLI scenario yourself for a benign and a ransomware case and read the output.

---

## Prompt 5: Backend API, WebSocket, database

```
Read docs/briefs/RULES.md and the fullstack demo brief (Section 6). Create branch feat/api. Do ONLY this task.

Build the FastAPI layer in backend/app/ with SQLite (SQLAlchemy, simple versioned migrations):
- All endpoints from Section 6 of the brief: status and control, processes, alerts (with evidence), release/confirm, scenarios (run, stop, runs, run detail with summary metrics), datasets (list, sample, stats, generate), models (list, train as a background job, evaluation, activate with a compatibility check, predict).
- WS /api/stream with message types window_scored, process_update, escalation, alert, containment, file_damage, rollback, scenario_state. Batch messages to avoid flooding.
- Health endpoint, CORS config, env + config.yaml settings, structured logging, graceful shutdown, auto-seed demo data on first start.
- Every simulated response carries simulated=true; every model response carries data_source.

Tests: API contract tests (pytest + httpx), a WS stream test, training job lifecycle, activation rejects an incompatible model.

Write docs/api.md with curl examples and confirm /docs (OpenAPI) loads. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```
**Before moving on:** start the server, open `/docs`, run a scenario with curl.

---

## Prompt 6: Frontend foundation and live dashboard

```
Read docs/briefs/RULES.md and the fullstack demo brief (Section 7, page 1). Create branch feat/dashboard. Do ONLY this task.

Set up frontend/ (React + TypeScript + Vite, Tailwind, Recharts, TanStack Query, shadcn/ui as needed), dark mode, responsive layout with sidebar navigation (all pages stubs except the dashboard), an API client typed from the OpenAPI schema, and a WebSocket hook with reconnect.

Build the Live Dashboard: a persistent "SIMULATED DEMO DATA" badge; top bar (mode, policy, active model plus its data origin, source); KPI cards; live process table (risk EWMA bar, level chip, status, Release/Confirm buttons under the manual policy); risk timeline chart with threshold lines at 0.3, 0.6, 0.85 and event markers; alert feed with an evidence drawer. Use virtualization for long lists and batch WS updates so it stays smooth. Loading, empty and error states everywhere. No hard-coded fake data.

Tests: component tests (vitest). Run the app against the real backend and describe what you saw. Save a screenshot in docs/demo/.

Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```
**Before moving on:** run backend and frontend, start a scenario, and watch the dashboard update.

---

## Prompt 7: Scenario runner, file-restore visual, detector comparison

```
Read docs/briefs/RULES.md and the fullstack demo brief (Section 5 and Section 7, pages 2 and 3). Create branch feat/scenarios. Do ONLY this task.

1. Scenario Runner page: cards for all 8 scenarios in Section 5 with description and expected outcome; controls for speed, seed, detector, policy; Run/Pause/Stop/Reset; a post-run result report (time-to-detect, files lost vs saved, false positives, containment latency, timeline) exportable as JSON and PDF.
2. File-system visualization: a grid or tree of files that turns "encrypted" for the attacking process, freezes at containment, and visibly restores on rollback. This is the key demo moment, so make it clear and smooth.
3. Detector Comparison page: the same scenario through rule_based, random_forest and xgboost side by side (run sequentially with the same seed if parallel is hard), with charts and a table of detection delay, files lost and false alarms.
4. Make sure "Mixed chaos" visibly shows independent per-process containment.

Tests: component tests and one Playwright smoke test that runs a scenario and asserts a containment appears. Save screenshots to docs/demo/. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```

---

## Prompt 8: Datasets page, Models and Training page, "Try it" widget

```
Read docs/briefs/RULES.md and the fullstack demo brief (Section 7, pages 4 and 5). Create branch feat/ml-ui. Do ONLY this task.

Datasets page: list with row counts and class balance chart, schema table, source mix, feature distribution explorer (per feature per class, overlap visible), filterable sample table, optional 2D projection scatter, a "Generate new dataset" form, and the rendered dataset card.

Models and Training page: registry table (active badge, data origin, metrics); train form (classifier, hyperparameters, dataset) with live progress and logs via WS; evaluation view (confusion matrix, ROC and PR curves, per-class and per-scenario-family metrics, feature importance, a threshold slider recomputing precision and recall, hard-test-set results shown separately and prominently); an Activate button with the compatibility check result; and a "Try it" widget with sliders for the 11 features showing live class probabilities and an explanation.

All numbers must come from the API. Add tests and screenshots in docs/demo/. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```

---

## Prompt 9: Alerts and forensics, settings, Guided Demo

```
Read docs/briefs/RULES.md and the fullstack demo brief (Section 7, pages 6 and 7, plus the Guided Demo requirement). Create branch feat/guided-demo. Do ONLY this task.

1. Alerts and Forensics page: filterable table; evidence drawer with the feature row, explanation chart, timeline, files touched, containment actions and latencies.
2. Settings page: theta0, window, EWMA alpha, thresholds, policy, auto-resolve timeout, allowlist editor, source selection, reset demo data. Changes must take effect in the backend.
3. Guided Demo: one button that auto-plays a roughly 3-minute story with on-screen captions: normal workday (no false alarm) -> nightly backup (no containment) -> fast ransomware (detect, freeze, rollback, files restored) -> detector comparison -> model metrics including the hard test set. Include pause and skip controls.
4. Write docs/demo_script.md: a presenter talk track matching the guided demo, including what to say about the synthetic-data limitation.

Add tests and screenshots. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```

---

## Prompt 10: Docker, CI, docs, final verification, push

```
Read docs/briefs/RULES.md and the fullstack demo brief (Sections 9, 10, 11). Create branch feat/demo-release. Do ONLY this task.

1. docker-compose.yml (backend + frontend/nginx), Makefile targets (demo, test, data, train), .env.example. `git clone && make demo` must work with no root and auto-seeded data.
2. CI (.github/workflows/ci.yml): ruff, backend pytest, frontend vitest, Playwright smoke test. Mark tests needing root or kernel features with a marker and skip them in CI.
3. Docs: README (install, run, architecture diagram, demo walkthrough), docs/architecture.md, docs/api.md, docs/limitations.md (honest: simulated sources are not real kernel traces, synthetic-trained models do not prove real-world accuracy, RealResponse and LiveAgentSource are unverified without a real VM).
4. Go through every acceptance criterion in Section 10 of the brief and report PASS / FAIL / NOT VERIFIED with evidence for each.
5. Ask me for the GitHub repo name and visibility, create the repo, push main and the branches, open a PR, and tag v0.2.0-demo.

Finish with the report format from RULES.md.
```
**Before moving on:** fresh clone in a clean folder, `make demo`, play the Guided Demo. The demo is now complete and showable.

---

## Prompt 11: Package layout, config, logging (agent)

```
Read docs/briefs/RULES.md and docs/briefs/antigravity_prompt_adaptshield_agent.md (Sections 2, 3, 6). Create branch feat/agent-core. Do ONLY this task.

1. Move to a src/ layout with pyproject.toml and console entry points (adaptshield, adaptshield-agent). Keep the existing tests passing. Reuse the feature schema and model registry from the demo work; do not duplicate them.
2. config.py: YAML config with documented defaults and validation (watch paths, excludes, protect_paths, mode, response policy, thresholds, allowlist, classifier mode, telemetry). Provide packaging/config.default.yaml.
3. Structured logging with rotation and journald support, replacing the bare print() in alert_logger.
4. Make the daemon take NO required CLI args: everything comes from config with defaults.
5. Make Tier-1/eBPF optional: if BCC or the kernel does not support it, run Tier-0-only and report it clearly.

Tests for config loading/validation and the Tier-0-only fallback. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```

---

## Prompt 12: Per-process containment, safety rails, state recovery

```
Read docs/briefs/RULES.md and the agent brief (Section 2 problems 4, 6, 7, 11 and Section 3.5). Create branch feat/agent-containment. Do ONLY this task.

1. Replace the single shared freezer cgroup in adaptshield/containment_manager.py with ONE cgroup per contained PID, with per-PID release. Regression test: contain two PIDs, release one, and the other stays frozen.
2. Safety rails: never contain PID 1, kernel threads, the agent and its children, systemd*, sshd, dbus, the login/display session, plus configurable allowlists by process name, exe path and user. Add rate limiting and a storm panic switch that drops to monitor mode with one high-severity alert.
3. Self-exclusion: ignore the agent's own PID, state dirs and quarantine/overlay activity so it can never trigger on itself.
4. Persist runtime state; on restart, recover frozen or pending PIDs and either resume the pending decision or release them per config. Add auto_resolve_after_seconds and auto_resolve_action for the manual policy.
5. A --dry-run mode that logs what would be done.

Unit tests for all of the above (root-only tests marked @pytest.mark.root). Give me exact commands to verify the cgroup behavior on a real Ubuntu VM, and state clearly if you could not run them in your sandbox. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```
**Before moving on:** run the VM cgroup verification commands and paste any failures back to Antigravity.

---

## Prompt 13: Overlay protection and multi-path watching

```
Read docs/briefs/RULES.md and the agent brief (Section 3.6 and Section 2 problems 3 and 5). Create branch feat/agent-protection. Do ONLY this task.

1. Multi-path fanotify watching with configured includes and default excludes. Document kernel and filesystem limitations honestly.
2. A protection manager that creates, mounts, remounts after reboot and cleans up the overlayfs for each directory in protect_paths, with quarantine and rollback wired to the per-PID containment from the previous prompt.
3. Fallback: if a path cannot be overlay-protected, log it, use quarantine-copy-on-detect plus freeze/kill for that path, and show "rollback unavailable" in status.
4. Do not touch user data destructively during tests; use temp dirs and loopback filesystems only.

Tests where possible; give exact VM verification commands for the rest. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```

---

## Prompt 14: Agent main loop, modes, ML auto-selection, hot reload

```
Read docs/briefs/RULES.md and the agent brief (Sections 3.2, 3.3, 3.4, 5). Create branch feat/agent-main. Do ONLY this task.

1. agent.py main loop wiring: config -> preflight -> cgroups -> protection layers -> classifier selection -> Tier-0 (plus Tier-1 if available) -> detection -> response. Handle SIGTERM/SIGINT (thaw frozen processes per policy, flush logs, unmount what we mounted) and SIGHUP (reload config and model).
2. Modes: monitor, protect, learn, with a configurable monitor-first period (default 24h, then auto-switch to protect).
3. Classifier auto-selection from the model registry: use a compatible model if present; otherwise fall back to rule_based with a loud warning; NEVER crash on a missing or incompatible model. Models with data_source=synthetic are NOT used for automatic containment unless classifier.allow_synthetic is true.
4. An optional rotating telemetry writer under /var/lib/adaptshield/telemetry/ for later labeling and retraining.
5. Explanations in alert records.

Tests for classifier selection, the synthetic guard, mode switching and signal handling. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```

---

## Prompt 15: The `adaptshield` CLI

```
Read docs/briefs/RULES.md and the agent brief (Section 4). Create branch feat/agent-cli. Do ONLY this task.

Build the `adaptshield` CLI with: status, doctor, run [--dry-run], alerts [--follow --since --json], list, show, release, confirm, mode, config check|show|edit, allowlist add|remove|list, model info|list|set|reload|rollback, train, evaluate, simulate benign|ransomware, version. All subcommands are thin wrappers over library code. Replace containment_cli.py (keep a compatibility shim). `doctor` checks kernel, cgroup v2 plus freezer, fanotify, BCC, model load and permissions.

Tests for CLI parsing and output. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```

---

## Prompt 16: Installer, systemd service, uninstall

```
Read docs/briefs/RULES.md and the agent brief (Section 2 problems 8 and 9, and Section 3.1). Create branch feat/agent-installer. Do ONLY this task.

1. install.sh: root, OS, kernel, cgroup, fanotify and eBPF preflight report (never abort just because eBPF is missing); install ONLY runtime apt dependencies; venv at /opt/adaptshield/venv with --system-site-packages; create /etc/adaptshield/config.yaml (never overwritten on upgrade), /var/lib/adaptshield and /var/log/adaptshield; install the `adaptshield` CLI on PATH; install and enable adaptshield.service (Restart=on-failure, ExecStopPost thaws frozen cgroups, hardening that does not break fanotify, eBPF or cgroups); idempotent; support --upgrade; finish by running `adaptshield doctor` and printing the running mode.
2. Move lab-only dependencies (sysbench, MySQL, PostgreSQL, restic, loopback test filesystems) behind --dev or setup/dev_lab_setup.sh.
3. uninstall.sh with --purge (the default keeps quarantined files and warns).
4. Stretch: a .deb build script.

You probably cannot run this in your sandbox. Say so, and give me an exact numbered verification checklist for a fresh Ubuntu 22.04/24.04 VM, including a reboot test. Finish with the report format from RULES.md. Commit. Do not start the next prompt's work.
```
**Before moving on:** run the checklist on your VM, including the reboot test, and paste any errors back.

---

## Prompt 17: Agent tests, CI, docs, acceptance, release

```
Read docs/briefs/RULES.md and the agent brief (Sections 8 and 9). Create branch feat/agent-release. Do ONLY this task.

1. Complete the tests: config, schema validation, safety rails, per-PID containment, registry, state recovery, CLI. Mark root and kernel tests and run only unit tests in CI.
2. CI workflow (ruff, pytest). Docs: a rewritten README (install, uninstall, config reference, modes, CLI, ML plug-in workflow), docs/architecture.md, docs/ml_integration.md, docs/threat_model.md, docs/limitations.md (overlay-only rollback scope, fanotify coverage, kernel requirements, synthetic-model caveat, not a replacement for backups).
3. Go through every acceptance criterion in Section 8 of the agent brief and report PASS / FAIL / NOT VERIFIED with evidence. I will run the VM checks you cannot run.
4. Update docs/PROGRESS.md, merge via PR, and tag v0.2.0.

Finish with the report format from RULES.md.
```

---

## If something goes wrong

- **Result is wrong or incomplete:** reply in the same chat with the failing output and say "Fix only this; do not start the next prompt."
- **It starts the next prompt on its own:** stop it and remind it of the rule.
- **A prompt is too big:** reply "Split this into two halves and report after the first."
- **Merging:** merge each branch into a `develop` branch after you review it, then branch the next prompt's work from `develop`.
