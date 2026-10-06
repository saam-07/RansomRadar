# AdaptShield — Step-by-Step Implementation Guide

This is the literal command sequence to go from a bare Ubuntu VM to final
results, matching the roadmap's Sections 3 and 9. Every command below was
either executed and verified in this session (`pytest`, classifier
sanity-check — see repo history) or is a standard, well-documented Linux
command; the pieces that need a real kernel/root (fanotify, eBPF, cgroups)
could not be executed in this sandboxed environment and MUST be run and
debugged on your actual Ubuntu VM — treat any error you hit there as
expected engineering work, not a sign something here is wrong.

---

## Phase 0 — Get the code onto your VM

```bash
# from your laptop, after downloading the adaptshield.zip artifact:
scp adaptshield.zip you@your-ubuntu-vm:~/
ssh you@your-ubuntu-vm
unzip adaptshield.zip -d ~/adaptshield_src
cd ~/adaptshield_src/adaptshield
```

## Phase 1 — Environment setup (roadmap §3 Step 1–2)

```bash
chmod +x setup/*.sh
sudo ./setup/install_deps.sh          # installs BCC, cgroup-tools, sysbench,
                                        # rsync/tar, python venv + requirements
source .venv/bin/activate

sudo ./setup/make_test_filesystems.sh  # creates & mounts ext4/btrfs/xfs
                                        # loopback images at /mnt/testfs_*

python -m pytest tests/ -v             # runs all 20 unit tests

sudo ./setup/verify_all.sh             # automated verification of the entire stack
```

**Verify before continuing:**
```bash
mount | grep testfs                    # 3 filesystems mounted
python3 -c "from bcc import BPF; print('BCC OK')"
cat /sys/fs/cgroup/cgroup.controllers  # should list "freezer"
```
If BCC import fails, your kernel headers likely don't match `uname -r` —
re-run `sudo apt install linux-headers-$(uname -r)` and reboot.

## Phase 2 — Bring up each module in isolation, in this order

Do **not** skip ahead to the full daemon until each of these individually
verifies. This mirrors roadmap §9 steps 3–6.

### 2a. Tier-0 watcher alone
```bash
# Run the tier0 watcher CLI in Terminal A:
sudo .venv/bin/python3 -m adaptshield.tier0_watcher --watch /mnt/testfs_ext4
```
In a second terminal: `for i in $(seq 1 100); do echo x >> /mnt/testfs_ext4/f$i.txt; done`
**Verify:** you should see your shell's PID appear with real-time rising `mod_rate` and `SUSPICION` scores.

### 2b. Tier-1 eBPF tracer alone
```bash
sudo .venv/bin/python3 -c "
from adaptshield.tier1_bridge import Tier1Tracer
import time, os
t = Tier1Tracer()
print('Tracer loaded. Escalating current shell subprocess test...')
t.escalate(os.getpid())
for _ in range(5):
    t.poll(timeout_ms=500)
    print(t.drain_events())
"
```
**Verify:** kprobes attach without error; events appear once you `write()`
inside the traced PID (e.g. run this in a script that also writes a file).

### 2c. Containment manager alone (BE CAREFUL — this freezes a real process)
```bash
sudo .venv/bin/python3 -c "
from adaptshield.containment_manager import ensure_cgroup_ready, freeze_pid, unfreeze_pid
import subprocess, time
ensure_cgroup_ready()
p = subprocess.Popen(['sleep', '30'])
t = freeze_pid(p.pid)
print('frozen at', t)
time.sleep(2)
unfreeze_pid()
p.wait()
"
```
**Verify:** `ps -o stat= -p <pid>` shows `T` (stopped) while frozen; the
`sleep 30` process takes noticeably longer than 30s wall-clock to exit
because it was paused mid-sleep.

## Phase 3 — Integration on ext4 only (roadmap §9 step 6)

```bash
mkdir -p /mnt/testfs_ext4/data /mnt/testfs_ext4/.overlay_upper /mnt/testfs_ext4/.overlay_work /mnt/testfs_ext4/.quarantine /mnt/testfs_ext4/merged
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
In another terminal, generate a benign burst, then a ransomware-like burst:
```bash
python3 dataset/benign_edit_mix.py --dir /mnt/testfs_ext4 --seed 1 --duration 20
python3 dataset/ransomware_sim.py --target-dir /mnt/testfs_ext4/data --mode full --rate 20 --seed 1
```
**Verify:** `tail -f results/raw/manual_test.jsonl` shows `escalation` then
`alert_critical` then `containment` events during the ransomware burst, and
nothing during the benign burst. With `--rollback-policy none` (shown
above), the containment event will show `"rolled_back": false` — this is
freeze-only, matching the original design. See Phase 3b below to actually
exercise reversibility.

## Phase 3b — Test reversible containment (IMMEDIATE and MANUAL policies)

**IMMEDIATE policy** — repeat Phase 3's ransomware-burst test but start the
daemon with `--rollback-policy immediate` instead of `none`. This time:
```bash
tail -f results/raw/manual_test.jsonl
```
should show a `containment` event with `"rolled_back": true`,
`"killed": true`, and a non-null `"quarantine_path"`. Verify directly:
```bash
ls /mnt/testfs_ext4/.overlay_upper        # should be EMPTY -- rollback wiped it
ls /mnt/testfs_ext4/.quarantine           # should contain a pid<N>_<timestamp>/ folder
cat /mnt/testfs_ext4/.quarantine/pid*/_manifest.json   # shows what was preserved
```
This is the concrete proof that reversible containment is real: the live
filesystem is restored (upperdir empty) while the touched files survive
in quarantine.

**MANUAL policy** — start the daemon with `--rollback-policy manual
--control-dir results/raw/control`, trigger a ransomware burst, then in a
third terminal:
```bash
python3 containment_cli.py list --control-dir results/raw/control
python3 containment_cli.py show --control-dir results/raw/control --pid <PID>
# false positive -> let it resume exactly where it was frozen, undamaged:
python3 containment_cli.py release --control-dir results/raw/control --pid <PID>
# OR, true positive -> quarantine + rollback + kill:
python3 containment_cli.py confirm --control-dir results/raw/control --pid <PID>
```
**Verify `release`:** the frozen process (check with `ps -o stat= -p <PID>`
before/after) resumes — `T` (stopped) becomes running again — and its
files in `.overlay_upper` are untouched, proving nothing was lost.
**Verify `confirm`:** identical outcome to the IMMEDIATE policy's rollback,
but only after your explicit command.

## Phase 4 — Train a real classifier before switching to `xgboost`/`random_forest` mode

The daemon's `random_forest`/`xgboost` options expect a **fitted** model.
Generate training data first, then fit and save a model:

```bash
# generate labeled traces for each workload class (repeat per filesystem)
for wl in benign backup_rsync oltp_mysql ransomware_full; do
  python3 dataset/generate_labeled_traces.py \
    --watch /mnt/testfs_ext4 --workload $wl \
    --workload-cmd -- python3 dataset/benign_edit_mix.py --dir /mnt/testfs_ext4 --seed 1 \
    --duration 60 --seed 1 --out results/raw/traces_${wl}_ext4_1.csv
done
```
Then train with the included `train_model.py` (no need to write it yourself
— it's already in the repo root):
```bash
python3 train_model.py --classifier xgboost --out results/processed/xgb_model.joblib
```
**Verify:** the printed "Row count by label" table shows all 4 classes
present with a reasonable number of rows each — if any class has only a
handful of rows, extend `--duration` for that workload and re-run before
trusting the saved model. If a class has fewer than 20 rows, `train_model.py`
will print an explicit warning telling you so.

**Before you have real kernel traces working yet:** you can sanity-check
that the training/daemon pipeline itself works, independent of real data
collection, using the bundled synthetic bootstrap generator:
```bash
python3 dataset/make_synthetic_bootstrap.py --rows-per-class 300
python3 train_model.py --include-synthetic --out results/processed/xgb_model.joblib
```
This trains on **synthetic, hand-authored feature distributions** — it
proves the code path works end to end, but the resulting model has learned
nothing about real ransomware behavior and must never be the source of any
number in your report. `train_model.py` prints a loud warning if you do
this so it's not accidentally forgotten.

## Phase 5 — Extend to btrfs and xfs (roadmap §9 step 8)

Re-run Phase 3 and Phase 4 pointed at `/mnt/testfs_btrfs` and
`/mnt/testfs_xfs`. Code should not change — if it breaks, the breakage
itself (e.g. `fanotify` behaving differently on a given filesystem) is a
finding to write up, not a bug to silently patch around.

## Phase 6 — Pilot run of the full pipeline

```bash
sudo .venv/bin/python3 -m experiments.experiment_runner --config experiments/configs/pilot.yaml
python3 -m analysis.aggregate
```
**Verify:** `results/processed/summary.csv` has one row per pilot cell,
`alert_rate_by_cell.csv` shows `ransomware` rows with high alert_rate and
`benign` rows with low alert_rate.

## Phase 7 — Full experimental matrix (roadmap §7.1, §9 step 9)

```bash
sudo .venv/bin/python3 -m experiments.experiment_runner --config experiments/configs/full_matrix.yaml
# this runs 480 timed cells; budget real wall-clock time (~60s workload +
# ~10s overhead per cell => several hours; run overnight, resumable by
# editing the manifest loop to skip already-completed rows)
```

## Phase 8 — Ablations (roadmap §8.1)

Re-run selected cells with each daemon flag from `daemon.py`'s argparser:
`--no-escalation`, `--no-tier1`, `--no-smoothing`, `--kill-instead-of-freeze`,
and sweep `--theta0` across e.g. `0.2, 0.35, 0.5, 0.65, 0.8`.

## Phase 9 — Analysis (roadmap §7.5–7.6, §9 step 11)

```bash
python3 -m analysis.aggregate
python3 -m analysis.plots
python3 -m analysis.significance
```
Figures land in `results/processed/figures/`; the significance table in
`results/processed/sigtest_cpu_overhead.csv`.

## Phase 10 — Write the paper (roadmap §9 step 13)

Use the section structure already given in the roadmap document
(`RansomGuard_Novel_OS_Project_Roadmap.md`, §9 step 13), pulling numbers
only from `results/processed/*.csv` — never from memory or expectation.

---

## Known gaps YOU still need to fill in (do not skip these)

1. **seccomp-bpf injection** into an already-running, uncooperative
   process is *not* implemented in `containment_manager.py` (documented
   there as an advanced/stretch goal) — freeze alone is the core,
   required mechanism; add seccomp injection only if time permits.
2. **renameat2/unlinkat kprobe symbol names** vary slightly across kernel
   builds — `tier1_bridge.py` already logs a warning and continues if one
   fails to attach; check that warning on your specific kernel and adjust
   the symbol name if needed (`sudo cat /proc/kallsyms | grep unlinkat`).
3. **sysbench DB credentials** — run `sudo ./setup/create_sysbench_db.sh`
   once (creates a `sbtest`/`sbtest`/`password` MySQL account matching
   `benign_workloads.py`'s defaults exactly). If you'd rather use different
   credentials or PostgreSQL, pass `--db-name/--db-user/--db-password/--db-host`
   to `benign_workloads.py sysbench` matching your own setup instead.
4. **WannaLaugh emulator / RADAR dataset** — genuinely third-party research
   artifacts, not bundled here; `dataset/ransomware_sim.py` is the safe,
   fully-working fallback the whole pipeline is built around. If you obtain
   WannaLaugh from its authors, swap it in as a second ransomware-workload
   generator and label traces by generator (`source` column, same pattern
   already used to distinguish real vs. synthetic traces in `train_model.py`).
5. **No pre-trained model is bundled** — `results/processed/*.joblib` does
   not exist until you run Phase 4. This is intentional: a model trained on
   my sandbox's synthetic data would not reflect your VM's actual kernel/
   filesystem behavior, and shipping one might tempt you to skip real data
   collection. Use `dataset/make_synthetic_bootstrap.py` only to test that
   the code runs, never as your reported model.

