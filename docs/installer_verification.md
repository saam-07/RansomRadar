# AdaptShield Installer & Systemd Verification Checklist

> **Environment Note:**
> This repository is developed in a multi-platform environment (Windows host / sandbox). Low-level Linux kernel components (`fanotify`, `cgroups v2 freezer`, systemd daemon, and `apt-get`) cannot be executed directly within the Windows development environment.
> The automated test suite (`pytest`) verifies all state tracking, config parsing, safety rails, fallback logic, and CLI interfaces.
> To verify full live production installation, execute the following numbered checklist on a fresh **Ubuntu 22.04 LTS** or **Ubuntu 24.04 LTS** virtual machine.

---

## Prerequisites for Target VM
- Clean Ubuntu 22.04 or 24.04 LTS instance (x86_64).
- Kernel >= 5.9 (Ubuntu 22.04 defaults to 5.15+, Ubuntu 24.04 defaults to 6.8+).
- Sudo/root access.
- Unified cgroups v2 enabled (default on Ubuntu 22.04+).

---

## Numbered Verification Checklist

### 1. Repository Setup
```bash
git clone https://github.com/saam-07/RansomRadar.git adaptshield
cd adaptshield
git checkout feat/agent-installer
```

---

### 2. Standard Production Installation
Run the installer without development tools:
```bash
sudo ./install.sh
```
**Expected Results:**
- Preflight report passes:
  - OS: `Ubuntu 22.04` or `24.04`
  - Kernel: `>= 5.9` (`[PASS]`)
  - cgroups v2: unified hierarchy (`[PASS]`)
  - fanotify: detected (`[PASS]`)
  - BCC / eBPF: reports status (if unavailable, notes Tier-0-only fallback readiness)
- Venv created at `/opt/adaptshield/venv`.
- Configuration placed at `/etc/adaptshield/config.yaml`.
- State directories created: `/var/lib/adaptshield`, `/var/log/adaptshield`.
- Binaries linked to `/usr/local/bin/adaptshield` and `/usr/local/bin/adaptshield-agent`.
- `adaptshield doctor` completes with diagnostics.
- Message output: `AdaptShield is running. Operating Mode: protect (with 24h monitor-first grace period)`.

---

### 3. Service Status and Logging
```bash
systemctl status adaptshield.service
journalctl -u adaptshield -n 20 --no-pager
```
**Expected Results:**
- `Active: active (running)`.
- Loaded from `/etc/systemd/system/adaptshield.service`.
- Logs show preflight completion, configuration loaded, classifier selected (`RuleBasedClassifier` or `XGBoost`), and event loop listening.

---

### 4. CLI Verification
```bash
adaptshield status
adaptshield doctor
adaptshield mode
adaptshield config show
```
**Expected Results:**
- `status` shows: Daemon status, active mode, uptime, detector type, and containment counts.
- `doctor` reports all green checks for kernel, cgroups, fanotify, and fallback subsystems.
- `mode` displays current mode (e.g. `monitor` or `protect`).

---

### 5. Upgrade Idempotency Test
Modify configuration and test upgrade:
```bash
echo "# Custom user marker" | sudo tee -a /etc/adaptshield/config.yaml
sudo ./install.sh --upgrade
grep "Custom user marker" /etc/adaptshield/config.yaml
```
**Expected Results:**
- Output indicates: `Existing configuration found at /etc/adaptshield/config.yaml. Preserving untouched.`
- Custom marker remains present in `/etc/adaptshield/config.yaml`.
- Systemd service is safely reloaded.

---

### 6. Development & Benchmark Lab Setup (`--dev`)
```bash
sudo ./install.sh --dev
```
**Expected Results:**
- Installs `sysbench`, `mysql-server`, `postgresql`, `restic`, `xfsprogs`, `btrfs-progs`.
- Executes `setup/create_sysbench_db.sh` to initialize MySQL benchmark tables.

---

### 7. End-to-End Simulation & Containment Test
Run safe built-in simulation:
```bash
adaptshield simulate ransomware --target /tmp/test_ransom_dir
adaptshield list
```
**Expected Results:**
- Process is flagged and contained.
- `adaptshield list` displays contained PID, status (`frozen`), policy, and overlay upper directory.

---

### 8. Release / False Positive Unfreezing
```bash
adaptshield release --all
adaptshield list
```
**Expected Results:**
- Releases contained processes and restores cgroup execution.
- `adaptshield list` returns `No contained or pending processes found.`

---

### 9. VM Reboot Persistence Test
```bash
sudo reboot
```
After VM comes back online:
```bash
ssh <user>@<vm-ip>
systemctl status adaptshield.service
adaptshield status
```
**Expected Results:**
- `adaptshield.service` automatically restarts on boot (`WantedBy=multi-user.target`).
- Daemon resumes monitoring without manual operator intervention.
- Protected overlay mounts are remounted cleanly.

---

### 10. Clean Uninstall and Purge
Test default uninstall (data preservation):
```bash
sudo ./uninstall.sh
```
**Expected Results:**
- Service stopped and disabled.
- CLI symlinks removed from `/usr/local/bin/`.
- Notice printed: `Preserved /var/lib/adaptshield/quarantine and /etc/adaptshield.`

Test purge uninstall:
```bash
sudo ./uninstall.sh --purge
```
**Expected Results:**
- Complete removal of `/etc/adaptshield`, `/var/lib/adaptshield`, `/var/log/adaptshield`, and `/opt/adaptshield`.
