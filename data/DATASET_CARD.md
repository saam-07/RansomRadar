# AdaptShield Dataset Card

## 1. Summary
This dataset contains synthetic feature traces designed to benchmark the **AdaptShield** ransomware detection and containment engine. It models the behavioral characteristics of benign developer workloads, legitimate high-volume backup processes, transactional OLTP database engines, and multiple evasive ransomware variants.

> **CRITICAL DISCLAIMER: SYNTHETIC DATA NOTICE**  
> All records in this dataset are generated from behavioral models and labeled as `source: synthetic`.  
> Synthetic-trained models demonstrate pipeline and risk-scoring functionality; performance on synthetic traces does **NOT** represent real-world detection efficacy or replace validation against real kernel instrumentation.

---

## 2. Schema Specification (Version 1.0.0)

| Column | Type | Role | Description |
|---|---|---|---|
| `pid` | int | Metadata | Operating system process identifier |
| `run_id` | str | Metadata | Unique process session run identifier (split grouping key) |
| `scenario` | str | Metadata | Benchmark scenario name |
| `label` | str | Target | Class: `benign`, `backup`, `oltp`, `ransomware` |
| `window_idx` | int | Temporal | Sequential 2-second window index within the run |
| `timestamp` | float | Temporal | Epoch timestamp of window snapshot |
| `source` | str | Provenance | Provenance tag (`synthetic`) |
| `mod_rate` | float | Tier-0 | File modification rate (events/sec) |
| `rename_rate` | float | Tier-0 | File rename rate (events/sec) |
| `create_del_rate` | float | Tier-0 | File create and delete rate (events/sec) |
| `event_count` | int | Tier-0 | Total raw fanotify events in window |
| `concentration_gini` | float | Tier-0 | Gini concentration coefficient of touched files |
| `t1_write_rate` | float | Tier-1 | eBPF traced sys_write rate (`NaN` if never escalated) |
| `t1_mean_entropy` | float | Tier-1 | Mean Shannon byte entropy of write buffers (`NaN` if never escalated) |
| `t1_entropy_std` | float | Tier-1 | Standard deviation of byte entropy (`NaN` if never escalated) |
| `t1_unlink_rate` | float | Tier-1 | eBPF traced sys_unlink rate (`NaN` if never escalated) |
| `t1_rename_rate` | float | Tier-1 | eBPF traced sys_rename rate (`NaN` if never escalated) |
| `t1_mean_write_size` | float | Tier-1 | Mean payload size of write syscalls (`NaN` if never escalated) |

---

## 3. Dataset Splits & Class Distributions

| Split | File | Distinct Runs | Row Count | Benign | Backup | OLTP | Ransomware | SHA-256 Checksum |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `train` | `raw/traces_train.csv` | 240 | 3600 | 1080 | 720 | 720 | 1080 | `52862955fade62f4...` |
| `val` | `raw/traces_val.csv` | 80 | 1200 | 360 | 240 | 240 | 360 | `f2785c876e6584b5...` |
| `test` | `raw/traces_test.csv` | 80 | 1200 | 360 | 240 | 240 | 360 | `7b4fa31f25a690ba...` |
| `hard_test` | `raw/traces_hard_test.csv` | 120 | 1800 | 300 | 300 | 300 | 900 | `fbc5cabf5019bde7...` |

### Split Integrity
- **Grouping:** All splits are grouped strictly by `run_id`. Zero `run_id` overlap exists across train, val, and test splits.
- **Held-out Hard Test:** `traces_hard_test.csv` contains evasion tactics (`slow_and_low`, `mimicry`) that **never appear in train or validation sets**, testing model generalization against unseen attack patterns.

---

## 4. Realistic Class Overlap Design
To avoid artificial separability:
1. **Backup vs. Ransomware:** Backup jobs compress archives, producing high `mod_rate` (25–85 ops/sec) and high entropy (5.4–6.85), overlapping with partial-encryption and mimicry ransomware.
2. **OLTP vs. Ransomware:** Database engines write WAL logs at high frequencies (15–65 ops/sec) with moderate entropy, overlapping with throttled and intermittent ransomware.
3. **Slow-and-Low Ransomware:** Emits low modification rates (2–12 ops/sec) to blend into benign background developer activity.
4. **Tier-1 Escalation Sentinels:** Unescalated processes preserve documented `NaN` values across all `t1_*` features, matching the real AdaptShield dual-tier operational architecture.

---

## 5. Generator Details
- **Generator Version:** `1.0.0`
- **Random Seed:** `42` (fixed master seed for bitwise reproducibility)
- **Generated At:** `2026-10-06T09:24:02.911709+00:00`
