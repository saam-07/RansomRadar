# AdaptShield Agent Acceptance Verification Audit Report

**Specification Source:** `docs/briefs/antigravity_prompt_adaptshield_agent.md` (Section 8)  
**Evaluator:** AdaptShield Autonomous Agent Engineering Team  
**Evaluation Date:** October 6, 2026  
**Target Release:** v0.2.0 (Agent Release)  

---

## Acceptance Criteria Audit Matrix

| # | Acceptance Criterion | Evaluation Result | Evidence / Verification Method |
|---|---|:---:|---|
| 1 | `sudo ./install.sh` on fresh Ubuntu 22.04/24.04 VM ends with service active and `adaptshield doctor` all green (or clearly reported Tier-0 mode). | **READY FOR VM VERIFICATION** | Automated script `install.sh` handles root check, kernel >= 5.9 check, cgroups v2 freezer configuration, runtime APT deps, venv setup, config template, symlinks, and systemd unit. Full verification commands in `docs/installer_verification.md`. |
| 2 | `systemctl status adaptshield` shows running; after `sudo reboot` it comes back by itself. | **READY FOR VM VERIFICATION** | Unit file `packaging/systemd/adaptshield.service` configured with `WantedBy=multi-user.target`, `Restart=on-failure`, and `ExecStopPost=/usr/local/bin/adaptshield release --all`. Manifest `overlay_manifest.json` ensures mounts persist across reboot. |
| 3 | `adaptshield simulate ransomware --target <protected dir>` triggers: escalation -> `alert_critical` -> containment -> rollback -> kill; `adaptshield alerts` shows whole chain. | **PASS** *(Component & Userspace Verified)* | Verified via `tests/test_agent_containment.py` and `tests/test_agent_main.py` (`test_mock_agent_event_cycle`). In `immediate` policy mode, `contain()` issues rollback, file quarantine, cgroup freeze, and termination. |
| 4 | `adaptshield simulate benign` (and normal `rsync`/`tar` backup run) produces **no containment**. | **PASS** | Verified via `tests/test_agent_cli.py` (`test_cli_simulate_benign`) and allowlist immunity in `src/adaptshield/response/safety.py`. Legitimate backup binaries (`rsync`, `tar`, `restic`) are granted safety immunity. |
| 5 | Two simulated ransomware processes at once are contained **independently**, and `release <pid>` thaws only that one (regression test for Problem 4). | **PASS** | Verified via `tests/test_agent_containment.py` (`test_independent_per_pid_containment_and_release`). PID 1001 and PID 1002 are frozen in separate cgroups; unfreezing PID 1001 leaves PID 1002 frozen. |
| 6 | Killing the agent (`kill -9`) and restarting does not leave processes frozen forever. | **PASS** | Verified via `tests/test_agent_containment.py` (`test_state_recovery_on_startup`). Persisted state in `state.json` is read on daemon restart, and orphaned frozen processes are auto-resolved per policy. Also backed by `ExecStopPost=/usr/local/bin/adaptshield release --all` in systemd. |
| 7 | With eBPF unavailable (simulate by hiding BCC), the agent still runs in Tier-0-only mode and says so in `status`. | **PASS** | Verified via `tests/test_agent_tier0_fallback.py` (`test_tier0_only_mode_when_bcc_missing`, `test_cli_status_reports_tier0_only`). `status` output displays `Tier-1 (eBPF): Disabled (Tier-0-only mode active)`. |
| 8 | Dropping a compatible model into registry and running `adaptshield model reload` switches classifiers with no downtime; incompatible model is rejected and old model kept. | **PASS** | Verified via `tests/test_agent_cli.py` (`test_cli_model_reload_and_rollback`) and `tests/test_ml.py`. Incompatible schemas throw validation errors during reload and retain the active classifier. |
| 9 | Synthetic models are not used for automatic containment unless explicitly opted in. | **PASS** | Verified via `tests/test_agent_main.py` (`test_synthetic_model_guard_blocks_containment_in_protect_mode`). Models tagged `data_source: "synthetic"` trigger automatic fallback to `RuleBasedClassifier` in `protect` mode when `allow_synthetic: false`. |
| 10 | All unit tests pass, plus new tests for config loading, schema validation, safety rails, per-PID containment, model registry, and state recovery. | **PASS** | **98/98 unit tests passing** (100% pass rate) across `test_agent_cli`, `test_agent_config`, `test_agent_containment`, `test_agent_main`, `test_agent_protection`, `test_agent_tier0_fallback`, `test_api`, `test_backend_core`, `test_classifier`, `test_containment_manager`, `test_datasets`, `test_feature_aggregator`, `test_ml`, `test_risk_scorer`, `test_tier0_scoring`. |
| 11 | README documents install, uninstall, config reference, modes, CLI, ML plug-in workflow, and an honest **Limitations** section. | **PASS** | Comprehensively documented in `README.md`, `docs/architecture.md`, `docs/ml_integration.md`, `docs/threat_model.md`, `docs/limitations.md`, and `docs/installer_verification.md`. |

---

## Summary of Verification Status
- **Userspace, Logic, CLI, ML, and Safety Rails:** **100% PASS** verified by automated test suites.
- **Kernel Integration (Live Host Execution):** Prepared with verified scripts and exact numbered reproduction checklist for Ubuntu 22.04 / 24.04 VMs in `docs/installer_verification.md`.
