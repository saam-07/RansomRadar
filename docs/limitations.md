# AdaptShield Limitations & Evasion Analysis

> **Notice:** Defensive security engineering requires complete transparency regarding detection boundaries, model degradations, and synthetic data constraints.

---

## 1. Synthetic vs. Real-World Telemetry

- **Synthetic Labeling:** All trace datasets (`data/raw/traces_*.csv`) and scenario runs in this demonstration are synthetically generated or simulated in user space.
- **Accuracy Disclaimers:** Synthetic-trained accuracy (e.g. 99.2% on benchmark splits) represents performance against modeled mathematical distributions, **not** guaranteed real-world protection against novel, polymorphic ransomware binaries.
- **In-Memory Filesystem:** The virtual filesystem grid simulates file encryption and rollback using in-memory state tracking. It does not perform actual cryptographic operations on physical disk blocks.

---

## 2. Evasion Tactics & Hard Test Set Degradation

During evaluation against the **Hard Test Set** (`traces_hard_test.csv`), which contains novel evasion behaviors withheld from training and validation splits, detector performance degrades significantly:

| Evaluation Metric | Standard Test Set | Hard Test Set (Evasive Variants) | Impact / Evasion Vulnerability |
|---|:---:|:---:|---|
| **Accuracy** | 99.2% | 67.3% | High evasion rates across subtle attacks |
| **Recall (Ransomware)** | 98.8% | **34.7%** | Misses 65% of novel evasion variants |
| **F1 Score** | 0.991 | **0.515** | Substantial degradation under evasion |
| **ROC-AUC** | 0.999 | 0.868 | Reduced discriminative boundary |

### 2.1 Evasion Techniques Evaluated:
1. **Slow-and-Low Pacing:** Attackers throttle encryption to 1-2 files per minute. This keeps write rates below detection thresholds and allows EWMA risk to decay between bursts.
2. **Rename-Then-Encrypt Separations:** Attacker renames hundreds of files in one phase, pauses, and encrypts in subsequent disjoint phases, evading single-window correlated feature checks.
3. **Partial Block Encryption:** Encrypting only the first 4KB of a file, leaving the remainder intact, which dampens whole-file write entropy calculations.
4. **Process Mimicry:** Injecting threads or masquerading as allowlisted processes (e.g. `rsync`, `postgres`).

---

## 3. Host & Kernel Requirements for Live Deployment

To transition from the simulated demonstration mode to real live kernel enforcement:
- **Linux Kernel:** Requires Linux Kernel $\ge 5.8$ with BTF (`CONFIG_DEBUG_INFO_BTF=y`) enabled for CO-RE eBPF probes.
- **cgroups v2:** Requires unified cgroup v2 hierarchy with `cgroup.freeze` controller enabled.
- **OverlayFS:** Requires `overlay` filesystem kernel module mounted over monitored protected user directories.
- **Root Privileges:** eBPF attachment and cgroup manipulation require `CAP_SYS_ADMIN` / `CAP_BPF` or root access.
- **Live Agent Telemetry:** Live mode requires the AdaptShield agent daemon running locally and piping structured events to `/var/log/adaptshield/alert.jsonl`.
