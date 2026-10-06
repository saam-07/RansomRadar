# AdaptShield — Complete Implementation Guide (v2, matches the zip with real reversible containment)

This supersedes the earlier setup guide. The daemon's command-line
interface changed (new required flags for reversible containment), so
use **this** version's commands, not the earlier one's.

---

## PART 1 — Prerequisites (what to download, before touching a terminal)

| # | What | Where from | Why |
|---|---|---|---|
| 1 | A hypervisor: VirtualBox (easiest) / VMware Player / QEMU-KVM | virtualbox.org / vmware.com / your Linux package manager | Runs the Ubuntu VM everything lives in |
| 2 | **Ubuntu Server 22.04 or 24.04 LTS ISO** | ubuntu.com/download/server | The OS — must be this range for kernel ≥5.9 and stable BCC/cgroups v2 |
| 3 | SSH client | Built into Mac/Linux terminal; Windows Terminal or PuTTY on Windows | Comfortable remote shell instead of the tiny VM console |
| 4 | `scp`/WinSCP | Built-in, or winscp.net | Copy `adaptshield.zip` onto the VM |
| 5 | VS Code + "Remote-SSH" extension (optional but recommended) | code.visualstudio.com | Edit files on the VM from your laptop |

**Hardware:** 8GB+ RAM host (16GB preferred), 40GB+ free disk, virtualization enabled in BIOS (Intel VT-x/AMD-V).

**You do NOT need:** any real malware, any downloaded ransomware dataset — everything ships with a safe built-in simulator. Everything else (BCC, cgroup-tools, rsync, sysbench, Python packages) installs automatically via `apt`/`pip` in Phase 2 below.

---

## PART 2 — Build the VM

1. Install VirtualBox. Restart if the installer asks.
2. New VM → Linux/Ubuntu 64-bit → 4096MB+ RAM → 60GB dynamic disk → 2+ CPUs.
3. Attach the Ubuntu ISO, boot, install (Server edition, use whole disk, create a user — remember the password).
4. On first boot, at the console:
   ```bash
   ip a                          # note the IP, e.g. 192.168.56.101
   sudo apt update
   sudo apt install -y openssh-server
   sudo systemctl enable --now ssh
   ```
5. From your **host terminal** from now on:
   ```bash
   ssh yourusername@192.168.56.101
   ```

---

## PART 3 — Get the code onto the VM

```bash
uname -r        # confirm >= 5.9 (Ubuntu 22.04/24.04 both fine, no action needed)
```
From your **host**, in the folder with `adaptshield.zip`:
```bash
scp adaptshield.zip yourusername@192.168.56.101:~/
```
Back on the **VM**:
```bash
unzip adaptshield.zip -d ~/adaptshield_src
cd ~/adaptshield_src/adaptshield
ls
```
You should see: `adaptshield/`, `analysis/`, `baselines/`, `dataset/`, `ebpf/`, `experiments/`, `instrumentation/`, `setup/`, `tests/`, `README.md`, `requirements.txt`, `setup.py`, `train_model.py`, `containment_cli.py`.

---

## PART 4 — Install everything

```bash
chmod +x setup/*.sh
sudo ./setup/install_deps.sh
```
Watch for `BCC OK` near the end. If it fails with a headers mismatch:
```bash
sudo apt install --reinstall linux-headers-$(uname -r)
sudo reboot
```
then SSH back in and re-run the install script.

This script now also runs `pip install -e .` for you — this is what makes `import adaptshield.xxx` work no matter which directory you run a script from. **Activate the venv every new terminal session:**
```bash
source .venv/bin/activate
```

Create the three test filesystems:
```bash
sudo ./setup/make_test_filesystems.sh
mount | grep testfs     # confirm ext4, btrfs, xfs all mounted
```

Run the unit tests (pure logic only, no kernel needed yet):
```bash
python -m pytest tests/ -v
```
**Expect: 20 passed** (this includes 7 tests specifically proving the quarantine/rollback logic works correctly).

You can also run the all-in-one verification script:
```bash
sudo ./setup/verify_all.sh
```

---

## PART 5 — Verify each kernel-facing module standalone

Do this before the integrated daemon — it isolates problems.

**5.1 — Tier-0 fanotify watcher.** Two terminals.

Terminal A:
```bash
# You can now run tier0_watcher directly as a standalone CLI:
sudo .venv/bin/python3 -m adaptshield.tier0_watcher --watch /mnt/testfs_ext4
```
Terminal B:
```bash
for i in $(seq 1 100); do echo x >> /mnt/testfs_ext4/f$i.txt; done
```
**Expect:** real-time event updates with PID and rising `mod_rate` and `SUSPICION` score.


**5.2 — Tier-1 eBPF tracer:**
```bash
sudo .venv/bin/python3 -c "
from adaptshield.tier1_bridge import Tier1Tracer
import time, os
t = Tier1Tracer()
print('Tracer loaded.')
t.escalate(os.getpid())
for _ in range(5):
    t.poll(timeout_ms=500)
    print(t.drain_events())
"
```
If you see a kprobe attach warning for `renameat2`/`unlinkat`, find the real symbol:
```bash
sudo cat /proc/kallsyms | grep -i renameat
```
and edit the matching `attach_kprobe(event=..., ...)` line in `adaptshield/tier1_bridge.py`.

**5.3 — Containment freeze:**
```bash
sudo .venv/bin/python3 -c "
from adaptshield.containment_manager import ensure_cgroup_ready, freeze_pid, unfreeze_pid
import subprocess, time
ensure_cgroup_ready()
p = subprocess.Popen(['sleep', '30'])
t = freeze_pid(p.pid)
print('frozen at', t)
time.sleep(3)
unfreeze_pid()
p.wait()
"
```
**Verify:** in another terminal, `ps -o stat= -p <pid>` shows `T` during the freeze window. If `ensure_cgroup_ready()` errors:
```bash
echo "+freezer" | sudo tee /sys/fs/cgroup/cgroup.subtree_control
```

---

## PART 6 — Run the integrated daemon (freeze-only first)

```bash
mkdir -p /mnt/testfs_ext4/data /mnt/testfs_ext4/.overlay_upper \
         /mnt/testfs_ext4/.overlay_work /mnt/testfs_ext4/.quarantine

sudo .venv/bin/python3 -m adaptshield.daemon \
    --watch /mnt/testfs_ext4 \
    --overlay-upper /mnt/testfs_ext4/.overlay_upper \
    --overlay-work /mnt/testfs_ext4/.overlay_work \
    --quarantine-dir /mnt/testfs_ext4/.quarantine \
    --rollback-policy none \
    --classifier rule_based \
    --window 2.0 \
    --log results/raw/manual_test.jsonl
```
**Note the new required flags** compared to earlier versions: `--overlay-work` and `--quarantine-dir` — the daemon will refuse to start without them now.

In a second terminal, tail the log; in a third, run a benign burst then a ransomware burst:
```bash
python3 dataset/benign_edit_mix.py --dir /mnt/testfs_ext4 --seed 1 --duration 20
for i in $(seq 1 50); do head -c 10000 /dev/urandom > /mnt/testfs_ext4/data/doc$i.dat; done
python3 dataset/ransomware_sim.py --target-dir /mnt/testfs_ext4/data --mode full --rate 20 --seed 1
```
**Expect:** `escalation` → `alert_critical` → `containment` (with `"rolled_back": false`, since policy is `none`) in the tailed log, and nothing during the benign burst.

---

## PART 7 — Test real reversible containment

**7.1 — IMMEDIATE policy (automatic rollback):**
Restart the daemon with `--rollback-policy immediate` instead of `none`, repeat the ransomware burst, then:
```bash
tail -f results/raw/manual_test.jsonl     # look for "rolled_back": true
ls /mnt/testfs_ext4/.overlay_upper        # should be EMPTY
ls /mnt/testfs_ext4/.quarantine           # should contain pid<N>_<timestamp>/
cat /mnt/testfs_ext4/.quarantine/pid*/_manifest.json
```

**7.2 — MANUAL policy (human-in-the-loop):**
```bash
sudo .venv/bin/python3 -m adaptshield.daemon \
    --watch /mnt/testfs_ext4 --overlay-upper /mnt/testfs_ext4/.overlay_upper \
    --overlay-work /mnt/testfs_ext4/.overlay_work \
    --quarantine-dir /mnt/testfs_ext4/.quarantine \
    --rollback-policy manual --control-dir results/raw/control \
    --classifier rule_based --window 2.0 --log results/raw/manual_test.jsonl
```
Trigger a ransomware burst, then in another terminal:
```bash
python3 containment_cli.py list --control-dir results/raw/control
python3 containment_cli.py show --control-dir results/raw/control --pid <PID>
# false positive:
python3 containment_cli.py release --control-dir results/raw/control --pid <PID>
# true positive:
python3 containment_cli.py confirm --control-dir results/raw/control --pid <PID>
```
**Verify release:** `ps -o stat= -p <PID>` shows the process transition from `T` back to running, files untouched. **Verify confirm:** same outcome as IMMEDIATE.

---

## PART 8 — Train real classifiers

Reset the filesystem, then collect labeled traces per workload:
```bash
sudo umount /mnt/testfs_ext4
sudo mkfs.ext4 -F ~/adaptshield_fsimages/testfs_ext4.img
sudo mount -o loop ~/adaptshield_fsimages/testfs_ext4.img /mnt/testfs_ext4
sudo chown $USER:$USER /mnt/testfs_ext4
mkdir -p /mnt/testfs_ext4/data /mnt/testfs_ext4/backup

python3 dataset/generate_labeled_traces.py --watch /mnt/testfs_ext4 --workload benign \
  --workload-cmd -- python3 dataset/benign_edit_mix.py --dir /mnt/testfs_ext4 --seed 1 --duration 60 \
  --duration 60 --seed 1 --out results/raw/traces_benign_ext4_1.csv

python3 dataset/generate_labeled_traces.py --watch /mnt/testfs_ext4 --workload backup_rsync \
  --workload-cmd -- python3 dataset/benign_workloads.py rsync --src /mnt/testfs_ext4/data --dst /mnt/testfs_ext4/backup \
  --duration 60 --seed 1 --out results/raw/traces_backup_ext4_1.csv

python3 dataset/generate_labeled_traces.py --watch /mnt/testfs_ext4 --workload ransomware_full \
  --workload-cmd -- python3 dataset/ransomware_sim.py --target-dir /mnt/testfs_ext4/data --mode full --rate 20 --seed 1 \
  --duration 60 --seed 1 --out results/raw/traces_ransomware_ext4_1.csv
```
For OLTP, first run the DB setup once:
```bash
sudo ./setup/create_sysbench_db.sh
```
then add an `oltp_mysql` trace the same way, using `dataset/benign_workloads.py sysbench --driver mysql --duration 60`.

Repeat each with different `--seed` values until every class has hundreds of rows, then:
```bash
python3 train_model.py --classifier xgboost --out results/processed/xgb_model.joblib
```

**Before real traces are ready**, you can sanity-check the ML pipeline itself:
```bash
python3 dataset/make_synthetic_bootstrap.py --rows-per-class 300
python3 train_model.py --include-synthetic --out results/processed/xgb_model.joblib
```
(Loudly warns this model must never produce a reported number.)

---

## PART 9 — Extend to btrfs and xfs

Repeat Parts 6–8 pointed at `/mnt/testfs_btrfs` and `/mnt/testfs_xfs`. No code changes should be needed — if something breaks only on one filesystem, that's a real finding for your report.

---

## PART 10 — Run the experiment matrix

Pilot first:
```bash
sudo .venv/bin/python3 -m experiments.experiment_runner --config experiments/configs/pilot.yaml
python3 -m analysis.aggregate
cat results/processed/alert_rate_by_cell.csv
```
Then the full matrix (run inside `tmux` — takes hours):
```bash
sudo apt install -y tmux
tmux new -s experiments
sudo .venv/bin/python3 -m experiments.experiment_runner --config experiments/configs/full_matrix.yaml
# Ctrl+B then D to detach; tmux attach -t experiments to resume
```
Then the reversibility-specific ablation:
```bash
sudo .venv/bin/python3 -m experiments.experiment_runner --config experiments/configs/reversibility_ablation.yaml
```

---

## PART 11 — Ablations, analysis, plots

```bash
python3 -m analysis.aggregate
python3 -m analysis.plots           # now includes fig4 (bytes vs quarantined) and fig5 (rollback rate)
python3 -m analysis.significance
```
Sweep `daemon.py`'s ablation flags manually: `--no-escalation`, `--no-tier1`, `--no-smoothing`, `--kill-instead-of-freeze`, and `--theta0 0.2/0.35/0.5/0.65/0.8`.

---

## PART 12 — Write the paper
Pull every number from `results/processed/*.csv` only.

---

## Troubleshooting quick reference

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'bcc'` | `sudo apt install --reinstall linux-headers-$(uname -r)`, reboot |
| `import adaptshield` fails from a script | `pip install -e .` wasn't run — re-run `sudo ./setup/install_deps.sh` |
| Daemon refuses to start, missing arg error | You're using an old command — this daemon now requires `--overlay-work` and `--quarantine-dir` |
| Kprobe attach warning | `sudo cat /proc/kallsyms \| grep -i <symbol>`, edit `tier1_bridge.py` |
| `cgroup.subtree_control` write fails | `echo "+freezer" \| sudo tee /sys/fs/cgroup/cgroup.subtree_control` |
| sysbench connection errors | Run `sudo ./setup/create_sysbench_db.sh` first |
| `containment_cli.py` says "no pending decision file" | Wrong `--control-dir` or `--pid`; check with the `list` subcommand first |
