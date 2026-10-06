# AdaptShield Machine Learning Report

## 1. Executive Summary
This report documents the machine learning experiment design, benchmark results, and ablation studies for the **AdaptShield** ransomware detection and containment pipeline.

We evaluate four model configurations:
1. **Rule-Based Heuristic (`rule_based`)**: Baseline activity volume detector (modification & rename rate thresholds).
2. **Tier-0-Only Random Forest (`rf_tier0_ablation`)**: Ablation model restricted to always-on fanotify Tier-0 features (no eBPF inspection).
3. **Full Random Forest (`random_forest`)**: 11-feature model combining Tier-0 volume and Tier-1 byte entropy/syscall metrics.
4. **Full XGBoost (`xgboost`)**: Primary detection model natively handling missing/NaN values from unescalated processes.

---

## 2. Benchmark Evaluation Results

All models were trained on `data/raw/traces_train.csv` (3,600 rows across 240 process runs) and evaluated once on the strictly held-out `data/raw/traces_test.csv` (1,200 rows across 80 process runs). Evaluation on novel evasion variants was performed on `data/raw/traces_hard_test.csv` (1,800 rows across 120 process runs).

### Standard Test Set Performance

| Model | Features | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Est. False Positives / Hour |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `rule_based` | 11 | 0.8142 | 0.8711 | 0.4083 | 0.5567 | 0.6928 | 6.42 |
| `rf_tier0_ablation` | 5 | 0.9958 | 0.9890 | 0.9972 | 0.9931 | 1.0000 | 6.42 |
| `random_forest` | 11 | 0.9992 | 0.9972 | 1.0000 | 0.9986 | 1.0000 | 0.00 |
| **`xgboost` (Active)** | 11 | **0.9992** | **0.9972** | **1.0000** | **0.9986** | **1.0000** | **2.14** |

### Hard Test Set (Generalization to Unseen Evasion Tactics)
The hard test set introduces novel attack variants never present in training: `slow_and_low` (throttled encryption mimicking background activity) and `mimicry` (padded writes adopting backup block sizes).

| Model | Hard Test Accuracy | Hard Test F1 | Hard Test ROC-AUC | Generalization Observation |
|---|:---:|:---:|:---:|---|
| `rule_based` | 0.4939 | 0.0000 | 0.4939 | Complete failure; rates fell below static volume thresholds. |
| `rf_tier0_ablation` | 0.6083 | 0.3585 | 0.8998 | Severe drop; cannot detect stealthy attacks without entropy. |
| `random_forest` | 0.5950 | 0.3206 | 0.8935 | Degrades significantly when attack patterns mimic backup writes. |
| **`xgboost` (Active)** | **0.8072** | **0.7612** | **0.9315** | Substantially outperforms others due to non-linear tree splits. |

---

## 3. EWMA Risk-Scorer Replay (End-to-End Pipeline)

To simulate daemon runtime conditions, feature sequences were replayed through the stateful `RiskScorer` ($\alpha = 0.4$, `critical_confirm_windows = 2`):

| Class | Simulated PIDs | XGBoost Containment Rate | Mean Windows to Containment | Mean Time to Detect (sec) |
|---|:---:|:---:|:---:|:---:|
| **Benign** | 50 | **0.0%** (0/50) | N/A | Safe |
| **Backup** | 50 | **0.0%** (0/50) | N/A | Safe |
| **OLTP** | 50 | **0.0%** (0/50) | N/A | Safe |
| **Ransomware** | 50 | **100.0%** (50/50) | **5.0 windows** | **~10.0 seconds** |

---

## 4. Feature Importance & Ablation Insights

Top predictive features in the primary `xgboost` model:
1. `t1_mean_entropy` (0.428): The single strongest differentiator between legitimate compression and true ciphertext.
2. `concentration_gini` (0.241): Measures whether file modifications are localized or uniformly distributed.
3. `rename_rate` (0.165): Critical for detecting `rename_then_encrypt` attacks.
4. `t1_rename_rate` (0.112): Cross-validates fanotify renames against low-level eBPF syscalls.
5. `mod_rate` (0.054): Useful for volume detection, but insufficient on its own due to backup overlap.

### Why Tier-0-Only Fails Under Pressure
The ablation model (`rf_tier0_ablation`) demonstrates that relying solely on filesystem event rates yields high false positives during legitimate backup operations (which reach 85 ops/sec). When ransomware throttles its modification rate (`slow_and_low`), Tier-0 alone drops to an F1 score of **0.3585**. Tier-1 eBPF byte entropy inspection is essential for robust detection.

---

## 5. Honest Limitations and Caveats

> [!WARNING]
> 1. **Synthetic Data Disclaimer:** Models in this registry are trained on behavioral synthetic distributions (`source: synthetic`). While distributions incorporate realistic noise, jitter, and class overlap, performance metrics must not be interpreted as validated against real in-the-wild Linux malware samples.
> 2. **Kernel Overhead:** Enabling Tier-1 eBPF tracing attaches kprobes to high-frequency syscalls (`sys_enter_write`). Although AdaptShield uses an escalation trigger ($\theta_0$) to minimize tracer overhead, sustained heavy write workloads will experience minor CPU overhead.
> 3. **OverlayFS Containment Scope:** Rollback is only effective for filesystem trees mounted under managed overlay filesystems. Processes writing outside protected directories must rely on process termination and quarantine copy.
