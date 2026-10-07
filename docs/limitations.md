# AdaptShield Limitations, Evasion Analysis & Operational Boundaries

> **Notice:** Defensive security engineering requires honest, complete transparency regarding detection boundaries, model degradations, filesystem constraints, and synthetic data caveats.

---

## 1. Not a Replacement for Backups

**AdaptShield is an active defense and containment layer, NOT a replacement for cold or offsite backups.**
- In destructive attacks that bypass userspace containment (e.g. disk corruption, direct block writes, or hardware failure), rollback is unavailable.
- Organizations MUST maintain air-gapped, immutable, or versioned backups (e.g. `restic`, `borg`, WORM storage, or remote cloud snapshots).

---

## 2. Filesystem & Kernel Constraints

### 2.1 OverlayFS Rollback Scope
- **Overlay-Only Rollback Scope:** Automated file restoration depends on OverlayFS upperdir isolation. Directories that are already mount points, read-only media, or filesystems that do not support OverlayFS lower/upper directories (such as certain pseudo-filesystems or NFS mounts with restricted POSIX attributes) cannot support overlay rollback.
- **Fallback Quarantine Mode:** If a protected path cannot be overlay-protected, AdaptShield logs the limitation honestly, engages `quarantine-copy-on-detect + freeze/kill`, and flags `rollback unavailable` in CLI diagnostics.
- See [`docs/filesystem_limitations.md`](filesystem_limitations.md) for full filesystem matrix (ext4, XFS, btrfs, ZFS, NFS).

### 2.2 Fanotify Coverage & Kernel Version Requirements
- **Kernel Version >= 5.9 Required:** Attributing filesystem events to specific calling process IDs (`PID`) and directory handles (`FAN_REPORT_DFID_NAME`) requires Linux kernel $\ge 5.9$. On older kernels, fanotify may report file modifications without PID attribution, disabling targeted per-PID containment.
- **Pseudo-Filesystems Excluded:** Kernel pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/run`) do not support fanotify notification marks and are explicitly excluded from monitoring.

---

## 3. Synthetic vs. Real-World Telemetry

- **Synthetic Training Data:** Baseline models (`xgb_model.joblib`, `rf_model.joblib`) were trained on synthetic benchmark traces (`synthetic_traces_bootstrap.csv`). They validate pipeline mechanics, schema contracts, and latency benchmarks, but have not observed polymorphic physical malware samples.
- **Synthetic Model Guard:** AdaptShield explicitly forbids synthetic-trained models from triggering automated containment in `protect` mode unless `classifier.allow_synthetic: true` is configured by the operator.
- **Accuracy Disclaimers:** 99.2% accuracy on synthetic benchmark splits does not guarantee zero-day resilience in production.

---

## 4. Detection Delay vs. Encryption Speed Tradeoff

- **Sliding Window Latency:** Tier-0 evaluation operates on sliding windows (default 2.0s). Rapid multi-threaded ransomware can encrypt dozens of small files within the initial 500ms before an alert window closes.
- **Role of OverlayFS:** Because zero-delay pre-execution detection is impossible without unacceptable false-positive impact on legitimate tools, AdaptShield relies on **OverlayFS atomic rollback** to guarantee that files touched before containment are restored immediately.

---

## 5. Evasion Tactics & Hard Test Set Degradation

Evaluation against the **Hard Test Set** (`traces_hard_test.csv`) with withheld evasion patterns demonstrates clear model degradation:

| Evaluation Metric | Standard Test Set | Hard Test Set (Evasive Variants) | Impact / Evasion Vulnerability |
|---|:---:|:---:|---|
| **Accuracy** | 99.2% | 67.3% | High evasion rates across subtle attacks |
| **Recall (Ransomware)** | 98.8% | **34.7%** | Misses 65% of novel evasion variants |
| **F1 Score** | 0.991 | **0.515** | Substantial degradation under evasion |
| **ROC-AUC** | 0.999 | 0.868 | Reduced discriminative boundary |

### Evasion Techniques & Attack Vectors:
1. **Slow-and-Low Pacing:** Attackers throttling encryption to 1-2 files per minute evade burst thresholds. EWMA risk smoothing mitigates this by accumulating evidence over time, but slow attacks take longer to flag.
2. **Rename-Then-Encrypt Phasing:** Renaming all files first, pausing, and encrypting hours later separates correlated signals.
3. **Partial Block Encryption:** Encrypting only file headers/footers minimizes entropy spikes across whole files.
4. **Allowlisted Process Injection:** Attackers executing within an allowlisted binary (e.g. `rsync`, `postgres`) are protected by immunity rails.
