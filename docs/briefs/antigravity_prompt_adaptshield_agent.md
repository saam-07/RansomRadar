# Prompt for Antigravity: Turn AdaptShield into an installable, fully autonomous agent

## 0. Your role and the goal

You are a senior Linux systems / security engineer. I am giving you an existing research prototype called **AdaptShield** (Python, Linux, ransomware detection and containment). Today it only works as a manual lab pipeline: I run many shell commands, pass many CLI flags, and start each module by hand.

**Your job is to productize it into an installable endpoint agent.** After a single install command, the agent must:

1. start on its own and survive reboots (systemd service),
2. watch the system continuously, with no flags and no manual steps,
3. run all detection (Tier-0 fanotify, Tier-1 eBPF escalation, features, classifier, risk scoring) automatically,
4. take containment actions automatically (freeze, quarantine, rollback, kill, depending on policy),
5. log everything and expose a simple control CLI,
6. live in a clean Git repository, structured so I can **plug in and retrain the ML model later** without touching the pipeline code.

Think of it like an antivirus or EDR agent: install once, it runs, it protects, I only look at status and alerts.

Work in the existing repo. Do not rewrite the core detection logic from scratch. Refactor, wrap and automate it, and fix the problems listed below.

---

## 1. What already exists (do not reinvent; reuse)

Package `adaptshield/`:

| File | Role |
|---|---|
| `fanotify_ctypes.py` | ctypes wrapper for fanotify (gives per-event PID) |
| `tier0_watcher.py` | Tier-0 always-on watcher; per-PID windowed features (`mod_rate`, `rename_rate`, `create_del_rate`, `event_count`, `concentration_gini`) and `tier0_suspicion_score()` |
| `tier1_bridge.py` + `ebpf/tier1_trace.bpf.c` | Tier-1 eBPF tracer (BCC), escalated per PID when Tier-0 score >= `theta0` |
| `feature_aggregator.py` | Merges Tier-0 and Tier-1 features. `FEATURE_COLUMNS` has 11 features |
| `classifier.py` | `RuleBasedClassifier`, `SklearnClassifier` (RF), `XGBClassifierWrapper`; `build_classifier(name)`; `.save()/.load()` via joblib |
| `risk_scorer.py` | EWMA smoothing, levels NONE/WATCH/SUSPECT/CRITICAL, needs N consecutive windows to reach CRITICAL |
| `containment_manager.py` | cgroup-v2 freezer, overlayfs diff, quarantine, rollback, kill, MANUAL decision files; `RollbackPolicy` = none / immediate / manual |
| `alert_logger.py` | JSONL event log |
| `daemon.py` | `AdaptShieldDaemon` wires everything together; `main()` needs many required CLI args |
| `containment_cli.py` (repo root) | list/show/release/confirm for manual decisions |

Other relevant files: `train_model.py`, `evaluate_model.py`, `dataset/` (workload and ransomware *simulators* for safe testing), `experiments/`, `analysis/`, `baselines/`, `setup/*.sh`, `tests/` (20 unit tests), `README.md`, `AdaptShield_Implementation_Guide_v2.md`.

Model files I already have: `results/processed/xgb_model.joblib` and `results/processed/rf_model.joblib`, trained on `results/raw/synthetic_traces_bootstrap.csv` (4 classes: benign, backup, oltp, ransomware; 500 rows each). **These are synthetic-data models. They prove the plumbing works but have not learned real ransomware behavior.** Treat them as placeholders (see Section 5).

---

## 2. Problems in the current code that block "install and it just runs"

Read the code and confirm each of these, then fix them. They are the reason the project is manual today.

1. **`daemon.py` has four required CLI args** (`--watch`, `--overlay-upper`, `--overlay-work`, `--quarantine-dir`), all pointing at lab test filesystems (`/mnt/testfs_ext4`). There is no config file, no defaults, no auto-discovery.
2. **`--model-path` is never auto-loaded.** Without it, the daemon builds an *unfitted* XGBoost/RF object and `predict_proba` will fail. Default must be safe (see Section 5).
3. **Overlay setup is manual.** Rollback only works if an overlayfs is already mounted with the right upper/work dirs. Nothing creates, mounts, remounts after reboot, or cleans these up.
4. **Containment uses ONE shared cgroup** (`ADAPTSHIELD_CGROUP`). `freeze_pid()` moves a PID into it, and `unfreeze_pid()` thaws *everything* in it. Containing two processes at once, or releasing one of them, is therefore broken. For an always-on agent this must become **one cgroup per contained PID** (or equivalent), with per-PID release.
5. **Fanotify watches a single path.** The agent needs multiple configured paths / mounts, with sane exclusions.
6. **No self-exclusion.** The agent's own log writes, quarantine copies and overlay activity would generate fanotify events and could trigger itself in a feedback loop. Exclude the agent's PID, its state directories, and its own children.
7. **No allowlist / safety rails.** Nothing prevents freezing or killing PID 1, systemd, sshd, the display server, a database, a package manager, a backup tool, or the agent itself. A security agent that bricks the machine is worse than none.
8. **`setup/install_deps.sh` installs lab-only software** (`mysql-server`, `postgresql`, `sysbench`, `restic`, `btrfs-progs`, `xfsprogs`) and then uses `sudo` internally. None of that belongs in an end-user install.
9. **No service management** (no systemd unit, no enable-on-boot, no restart-on-failure, no graceful shutdown that thaws frozen processes).
10. **Logging is a bare JSONL file plus a `print()`.** No rotation, no levels, no journald integration, no machine-readable status.
11. **Stateful pieces are in memory only.** After a crash or restart, any frozen-and-awaiting-decision PIDs are orphaned in a frozen cgroup forever.
12. **eBPF/BCC is a hard dependency.** If the kernel headers or BCC are missing, the whole daemon fails. It should degrade gracefully to Tier-0-only mode and say so clearly.
13. **No input validation on features before `predict_proba`** (missing columns, NaN-only rows, `pid` column leaking into features, etc.).
14. **Mixed layout:** `containment_cli.py`, `train_model.py`, `evaluate_model.py` sit at repo root and depend on `PYTHONPATH=.`. They should be proper entry points of the installed package.

---

## 3. Target behavior ("what the user experiences")

### 3.1 Install

One command on Ubuntu 22.04/24.04 (kernel >= 5.9):

```bash
git clone <repo> && cd adaptshield
sudo ./install.sh
```

Also provide, as a stretch deliverable, a `.deb` build (`make deb` or a `packaging/` script) producing `adaptshield_<version>_amd64.deb` that does the same thing through `dpkg -i`.

`install.sh` must:

- check root, OS, kernel version, cgroup v2 + freezer, fanotify support, and whether BCC/eBPF works; print a clear preflight report; **never abort just because eBPF is missing**, instead enable Tier-0-only mode and record that in the install report;
- install only *runtime* apt dependencies (BCC, clang/llvm/libbpf/headers if eBPF is wanted, cgroup tools, python3-venv, etc.). Lab dependencies (sysbench, MySQL, PostgreSQL, restic, loopback test filesystems) move behind `sudo ./install.sh --dev` or a separate `setup/dev_lab_setup.sh`;
- create a venv at `/opt/adaptshield/venv` (with `--system-site-packages` so apt's `python3-bpfcc` is importable), install the package there;
- create and own these paths:
  - `/etc/adaptshield/config.yaml` (created from a documented template, never overwritten on upgrade),
  - `/var/lib/adaptshield/` (state, models, quarantine, overlays, control files),
  - `/var/log/adaptshield/` (logs),
- install a systemd unit `adaptshield.service` (Type=simple or notify, `Restart=on-failure`, `ExecStopPost` that thaws any frozen cgroups, sensible hardening that does not break fanotify/eBPF/cgroups), run `systemctl daemon-reload`, `enable --now`;
- install the `adaptshield` CLI on PATH (symlink in `/usr/local/bin`);
- be **idempotent** (safe to run twice) and support `--upgrade`;
- finish by running `adaptshield doctor` and printing "AdaptShield is running" plus the mode it started in;
- ship `uninstall.sh` (`--purge` optionally removes state/quarantine; default keeps quarantined files and warns).

### 3.2 Runtime (fully automatic)

- `adaptshield-agent` (or `python -m adaptshield.agent`) is the systemd entry point. It takes **no required arguments**; everything comes from `/etc/adaptshield/config.yaml` with defaults.
- On start it automatically: loads config, runs preflight/self-test, sets up cgroups, sets up/mounts protection layers (overlay etc.), chooses classifier (Section 5), starts Tier-0, starts Tier-1 if available, then loops forever running detection and response.
- The existing detection chain stays: Tier-0 snapshot -> (`score >= theta0`) -> Tier-1 escalation -> feature rows -> classifier -> EWMA risk -> CRITICAL -> containment.
- Handles `SIGTERM/SIGINT` cleanly (thaw frozen processes unless policy says otherwise, flush logs, unmount what it mounted).
- Handles `SIGHUP` to reload config (and model) without restart.
- Recovers state after restart: reads a persisted state file, finds frozen-and-pending PIDs and either resumes the pending decision or releases them per config.

### 3.3 Operating modes (config key `mode`)

| Mode | Behavior |
|---|---|
| `monitor` | Detect and log only. No freezing, killing or rollback. |
| `protect` (default after learning period, see below) | Detect and act automatically per `response.policy`. |
| `learn` | Collect feature rows/labels-free telemetry to `/var/lib/adaptshield/telemetry/` for later model training; no response actions. |

Ship with a configurable `monitor`-first period (default: first 24 h in `monitor`, then auto-switch to `protect`; configurable or disabled). Document this clearly in the README.

### 3.4 Response policy (config key `response.policy`)

Keep the existing three policies and make them work unattended:

- `none`: freeze only.
- `immediate`: freeze -> quarantine touched files -> rollback overlay -> kill. Fully automatic.
- `manual`: freeze, then wait for a human decision via the CLI. **Add `auto_resolve_after_seconds` + `auto_resolve_action` (`release` or `confirm`)** so an unattended machine never leaves a process frozen forever.

Default for the shipped config: `immediate` for CRITICAL, but only for PIDs that pass the safety rails below.

### 3.5 Safety rails (mandatory)

- Never contain: PID 1, kernel threads, the agent and its children, `systemd*`, `sshd`, `dbus`, the login/display session, anything in a configurable `allowlist.process_names` / `allowlist.exe_paths` / `allowlist.users`.
- Default allowlist includes common legitimate heavy writers (package managers `apt/dpkg`, `rsync`, `tar`, `restic`, `borg`, DB servers, IDE indexers) but still logs them at WATCH/SUSPECT level.
- Rate-limit containments (e.g. max N per minute) and add a **panic switch**: if more than N distinct PIDs go CRITICAL within M seconds, drop to `monitor` and raise one high-severity "possible false-positive storm" alert instead of freezing the machine.
- Dry-run flag: `adaptshield run --dry-run` logs what it *would* do.

### 3.6 Paths and filesystems (config key `watch`)

- Defaults: user home directories and `/srv`, `/var/www`, `/opt/data` if present; user-extensible list of paths and mounts.
- Default excludes: `/proc /sys /dev /run /tmp(optional) /var/lib/adaptshield /var/log/adaptshield /var/cache/apt` plus the agent's own paths.
- Multiple fanotify marks (per mount or per directory as the kernel allows). Document kernel/filesystem limitations honestly.
- **Rollback layer:** keep the overlayfs design but make the agent create and manage the overlay for each *protected directory* declared in config (`protect_paths`). If a path cannot be overlay-protected (unsupported fs, already a mountpoint, etc.), the agent logs it and falls back to `quarantine-copy-on-detect + freeze/kill` for that path, with a clear status line saying that rollback is **unavailable** for it. Be explicit about this limitation in the docs rather than hiding it.

---

## 4. CLI to build (`adaptshield ...`)

All subcommands are thin wrappers over library code (no duplicated logic):

```
adaptshield status                 # service state, mode, tier-1 on/off, classifier in use, uptime, counters
adaptshield doctor                 # preflight: kernel, cgroup v2, freezer, fanotify, BCC, model load, permissions
adaptshield run [--dry-run]        # foreground run (what systemd calls; also useful for debugging)
adaptshield alerts [--follow] [--since 1h] [--json]
adaptshield list                   # currently contained / pending-decision PIDs
adaptshield show <pid>
adaptshield release <pid>          # false positive: thaw
adaptshield confirm <pid>          # true positive: quarantine + rollback + kill
adaptshield mode <monitor|protect|learn>
adaptshield config check|show|edit
adaptshield allowlist add|remove|list
adaptshield model info|list|set <path>|reload|rollback
adaptshield train [--data ...] [--classifier xgboost|random_forest]   # wraps train_model.py
adaptshield evaluate [--data ...]                                      # wraps evaluate_model.py
adaptshield simulate benign|ransomware [--target DIR]                  # wraps dataset/*_sim.py, for safe end-to-end demo
adaptshield version
```

`containment_cli.py` is replaced by `list/show/release/confirm` above (keep a thin compatibility shim if you like).

---

## 5. ML integration design (this is the part I will extend later)

I will later train and drop in a better model. Build the seam properly now.

- **Model registry directory:** `/var/lib/adaptshield/models/` with a `current` symlink and a `manifest.json` per model: `{name, classifier_type, trained_at, feature_columns, feature_schema_version, data_source: "real"|"synthetic", metrics, sha256}`.
- **Classifier selection at startup (config `classifier.mode: auto`):**
  1. if a model in the registry loads and its `feature_columns` match the current `FEATURE_COLUMNS` and validation passes -> use it;
  2. else fall back to `RuleBasedClassifier` and log a loud warning;
  3. never crash because a model is missing or incompatible.
- **Synthetic-model guard:** the two `.joblib` files I have were trained on synthetic data. Register them as `data_source: "synthetic"`. By default (`classifier.allow_synthetic: false`) the agent uses the rule-based classifier in `protect` mode and only uses a synthetic model in `monitor`/`learn` mode or when I explicitly set `allow_synthetic: true`. `adaptshield status` must show which of these is active. Do not silently present synthetic-trained detection as production-grade.
- **Stable interface:** define an abstract `Classifier` protocol (`predict_proba(df) -> ndarray`, `feature_columns`, `save/load`, `version`). `build_classifier()` becomes plugin-friendly so I can add `lightgbm`, a neural net, or an ensemble without editing the daemon.
- **Feature contract:** a single `features/schema.py` (version string + column list + dtype + NaN semantics). Daemon validates every row against it: drop `pid`/`label` before inference, handle NaN Tier-1 columns when Tier-1 is off, never feed a column the model was not trained on.
- **Hot reload:** `adaptshield model reload` or `SIGHUP` swaps the model atomically with no downtime. If the new model fails validation, keep the old one.
- **Data flywheel:** in every mode, optionally write feature rows (plus PID/process name/exe hash/timestamp, and the action taken) to `/var/lib/adaptshield/telemetry/*.parquet|csv` with rotation and size cap, so I can later label them and retrain. `adaptshield train` consumes `telemetry/` and `results/raw/traces_*.csv`.
- Keep `train_model.py` / `evaluate_model.py` behavior (including its synthetic-data warnings) but move them into `adaptshield/ml/` and expose them via the CLI.
- Also expose a per-decision **explanation** in alert records (top feature contributions or the rule that fired) so alerts are explainable.

---

## 6. Repository structure (target)

```
adaptshield/                       # repo root
├── pyproject.toml                 # replaces setup.py; console_scripts: adaptshield, adaptshield-agent
├── README.md                      # rewritten: install, quickstart, modes, config, architecture, limitations
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── .gitignore                     # .venv, __pycache__, results/raw/*.csv, *.joblib (see note), state dirs
├── install.sh / uninstall.sh
├── packaging/                     # systemd unit, deb build, default config template
│   ├── adaptshield.service
│   └── config.default.yaml
├── src/adaptshield/
│   ├── agent.py                   # main loop, signals, lifecycle
│   ├── config.py                  # YAML load, defaults, validation (pydantic or dataclasses)
│   ├── cli.py
│   ├── detection/                 # tier0_watcher, tier1_bridge, feature_aggregator, risk_scorer, fanotify_ctypes
│   ├── ebpf/tier1_trace.bpf.c
│   ├── response/                  # containment_manager (per-PID cgroups), overlay manager, quarantine, safety rails
│   ├── ml/                        # classifier, registry, schema, train, evaluate
│   ├── logging/                   # structured logging, alert logger, rotation, journald
│   └── state.py                   # persisted runtime state / recovery
├── dataset/                       # simulators (benign + ransomware) used by `adaptshield simulate`
├── experiments/ analysis/ baselines/   # research code stays, clearly marked as non-runtime
├── docs/                          # architecture.md, ml_integration.md, threat_model.md, limitations.md
├── tests/                         # unit + integration
└── .github/workflows/ci.yml       # lint (ruff), type check (mypy, lenient), pytest on every push
```

You may adjust the layout if you have a strong reason, but keep: package under `src/`, console entry points, config/state/log separation, research code isolated from runtime code.

**Model files in Git:** do not commit large or secret data blindly. Commit the two small existing `.joblib` files under `models/placeholder/` with a README that says they are synthetic, or use Git LFS / release assets. Never commit real telemetry.

---

## 7. Git / repo tasks

1. `git init` (if needed), sensible `.gitignore`, first commit of the *unchanged* prototype tagged `v0.1.0-prototype` so history is preserved.
2. Do the refactor on a branch `feat/autonomous-agent` in small, well-named commits (conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`).
3. Create the GitHub repo (ask me for the name/visibility if you cannot infer it), push `main` + the branch, open a PR describing the changes.
4. Add CI (GitHub Actions) running ruff + pytest (unit tests only; tests needing root/kernel features are marked `@pytest.mark.root` and skipped in CI).
5. Tag `v0.2.0` once Section 8 acceptance passes.

---

## 8. Acceptance criteria (prove it, do not just claim it)

Run what you can in a real environment (an Ubuntu VM, root). For anything you cannot execute (for example your sandbox lacks fanotify/eBPF/cgroup access), say so explicitly and give me the exact commands to verify it. **Do not claim kernel-level features work unless you ran them.**

1. `sudo ./install.sh` on a fresh Ubuntu 22.04/24.04 VM ends with the service active and `adaptshield doctor` all green (or clearly-reported degraded Tier-0-only mode).
2. `systemctl status adaptshield` shows running; after `sudo reboot` it comes back by itself.
3. `adaptshield simulate ransomware --target <protected dir>` triggers, with no other manual step: escalation -> `alert_critical` -> containment -> rollback (when overlay-protected) -> kill; `adaptshield alerts` shows the whole chain, and the protected directory is restored.
4. `adaptshield simulate benign` (and a normal `rsync`/`tar` backup run) produces **no containment**.
5. Two simulated ransomware processes at once are contained **independently**, and `release <pid>` thaws only that one (regression test for Problem 4).
6. Killing the agent (`kill -9`) and restarting does not leave processes frozen forever.
7. With eBPF unavailable (simulate by hiding BCC), the agent still runs in Tier-0-only mode and says so in `status`.
8. Dropping a new compatible model into the registry and running `adaptshield model reload` switches classifiers with no downtime; an incompatible model is rejected and the old one is kept.
9. Synthetic models are not used for automatic containment unless I opt in.
10. All existing 20 unit tests still pass, plus new tests for config loading, schema validation, safety rails, per-PID containment, model registry, and state recovery.
11. README documents install, uninstall, config reference, modes, CLI, ML plug-in workflow, and an honest **Limitations** section (overlay-only rollback scope, fanotify coverage, kernel version requirements, synthetic-model caveat, not a replacement for backups).

---

## 9. Constraints and working style

- **Defensive tool only.** The ransomware simulator must remain the existing safe simulator that only touches a user-specified target directory. Do not add real malware, evasion techniques, or anything that operates outside the target directory.
- Keep the code readable and commented; this is a long-lived project that I will extend with ML.
- Prefer small, reviewable changes over a giant rewrite. Keep the research/experiment code working.
- Where the existing code has a known limitation (README "Known gaps"), do not paper over it; document it in `docs/limitations.md`.
- Before you start coding, give me a short plan (files to change, order of work, risks), then proceed phase by phase: (1) repo + packaging skeleton, (2) config + agent entry point, (3) per-PID containment + safety rails + state recovery, (4) overlay/protection manager, (5) ML registry + schema + auto classifier selection, (6) CLI, (7) installer + systemd + doctor, (8) tests + CI, (9) docs, (10) push + PR. After each phase, summarize what changed and how you verified it.
- If something is ambiguous (repo name, default watch paths, default policy), pick a sensible default, state it, and keep going. Ask me only if a wrong guess would be costly or hard to undo.

**Start now with the plan.**
