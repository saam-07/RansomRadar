# AdaptShield 3-Minute Guided Demo Script

> **Defensive Security Disclaimer:** AdaptShield is a defensive host-security engine. All ransomware activity in this demonstration is simulated in memory using synthetic feature traces and throwaway virtual files. Synthetic performance metrics do not represent field efficacy against real-world zero-day polymorphic threats.

This script guides presenters and evaluators through the 3-minute interactive narrative demonstrated in the UI (available via the **"Guided Demo (3 Min)"** button in the top navigation bar).

---

## Story Overview

| Step | Topic | Scenario / Action | Key Technical Takeaway |
|:---:|---|---|---|
| **1** | **Quiet Baseline** | `normal_workday` | Typical developer edits; EWMA stays < 0.15, well below 0.30 WATCH threshold. Zero containments. |
| **2** | **High I/O Stress** | `nightly_backup` | Rsync writes hundreds of files rapidly; entropy remains normal (~4.1). Zero false positives. |
| **3** | **Active Outbreak & Rollback** | `fast_ransomware` | High-entropy writes (>7.8) + rename flood; contained in 3 windows (~6s); cgroup frozen in 3.8ms; overlayfs restored in 4.2ms. Zero files lost. |
| **4** | **Side-by-Side Benchmark** | Detector Comparison | Rule-Based is slow (4 files lost); Random Forest catches it at window 4; XGBoost contains at window 3 (1 file exposed, restored cleanly). |
| **5** | **Evaluation & Hard Test Reality** | Models & Registry | XGBoost achieves 99.2% F1 on known data, but drops to 34.7% recall on the Hard Test Set (novel evasion). Proves necessity of defense-in-depth. |

---

## Step 1: Normal Workday (Quiet Baseline)

- **UI Navigation:** Navigate to **Live Dashboard** or click **"Guided Demo" -> Step 1**.
- **Action:** Click **"Simulate Normal Workday"** (speed: 20x, seed: 42).
- **Presenter Narration:**
  > "Welcome to AdaptShield. We start our evaluation during a normal workday. Developer activity involves file edits, git commits, code compiles, and IDE saves. Notice the Live Process table: even during bursts of code generation, the EWMA risk score remains below 15%, cleanly under our 30% WATCH threshold. Zero processes are frozen, and the virtual filesystem remains 100% intact."
- **Expected Metrics:**
  - Evaluated windows: 18
  - Active PIDs: 3
  - Contained PIDs: 0
  - Files intact: 300 / 300

---

## Step 2: Nightly Backup (High I/O Stress Test)

- **UI Navigation:** Click **"Guided Demo" -> Step 2**.
- **Action:** Click **"Simulate Nightly Backup"** (speed: 20x, seed: 42).
- **Presenter Narration:**
  > "Next, we subject the engine to high I/O stress: a nightly automated backup using rsync and tar. Naive security tools that alert purely on modification velocity fail here, triggering false alarms and halting critical backup jobs. AdaptShield extracts Tier-1 write entropy and rename rates. Because backup files have moderate entropy (3.8 to 4.5) and near-zero rename volume, AdaptShield classifies the traffic as benign backup activity. Result: zero containments, zero business disruption."
- **Expected Metrics:**
  - Peak modification rate: 85+ events / window
  - Contained PIDs: 0
  - False alarms: 0

---

## Step 3: Fast Ransomware (Active Outbreak & Rollback)

- **UI Navigation:** Click **"Guided Demo" -> Step 3** or navigate to **Scenario Runner**.
- **Action:** Click **"Trigger Outbreak & Rollback"** (`fast_ransomware`, speed: 10x, seed: 42).
- **Presenter Narration:**
  > "Now, an active adversary executes fast ransomware. The attacker rapidly encrypts documents while appending extensions. Watch the timeline: within 3 evaluation windows (approximately 6 seconds), write entropy jumps to 7.92, rename rate surges, and the process risk score crosses 85% CRITICAL. AdaptShield triggers independent per-process containment: cgroup v2 freezes the attacking PID in 3.8ms, preventing further encryption. The overlayfs layer immediately rolls back all encrypted files to pristine baseline in 4.2ms. The user loses zero files."
- **Expected Metrics:**
  - Detection delay: 3 windows (6.0 seconds)
  - Containment latency: 3.8 ms freeze, 4.2 ms rollback
  - Files lost: 0
  - Files restored: All encrypted files restored cleanly

---

## Step 4: Side-by-Side Detector Benchmark

- **UI Navigation:** Click **"Guided Demo" -> Step 4** or navigate to **Detector Comparison**.
- **Action:** Click **"Run Side-by-Side Comparison"** (`fast_ransomware`, seed: 42).
- **Presenter Narration:**
  > "Why use machine learning over traditional heuristic rules? Here we run the identical attack seed through three detection engines side by side. Rule-based heuristics require rigid threshold breaches, delaying containment until window 6 and exposing 4 user files to permanent loss. Random Forest detects earlier at window 4. XGBoost achieves minimal detection delay: containing the threat at window 3, preserving 59 of 60 files before atomic rollback restores the final file."
- **Benchmark Table:**

| Metric | Rule-Based Heuristic | Random Forest (100 Trees) | XGBoost (Gradient Boosted) |
|---|:---:|:---:|:---:|
| **Time to Detect** | 6 windows (12.0s) | 4 windows (8.0s) | **3 windows (6.0s)** |
| **Files Exposed Before Containment** | 4 files | 2 files | **1 file** |
| **Files Saved / Restored** | 56 / 4 | 58 / 2 | **59 / 1** |
| **Containment Action Latency** | ~4 ms | ~4 ms | **~4 ms** |

---

## Step 5: Model Evaluation & Hard Test Set Reality

- **UI Navigation:** Click **"Guided Demo" -> Step 5** or navigate to **Models & Training**.
- **Presenter Narration:**
  > "Honesty about machine learning limitations is essential in defensive security. On standard validation and test splits with familiar ransomware variants, our XGBoost detector achieves 99.2% accuracy and 0.991 F1 score. However, look at the Hard Test Set banner: when confronted with novel evasion techniques—such as slow-and-low throttling, partial block encryption, and rename-then-encrypt sequences—recall drops to 34.7%. This proves that standalone ML is insufficient. AdaptShield couples ML detection with strict kernel safety rails, process allowlists, and reversible snapshots to ensure layered, resilient defense."
- **Evaluation Summary:**
  - **Standard Test Split:** Accuracy: 99.2%, F1 Score: 0.991, ROC-AUC: 0.999
  - **Hard Test Set (Novel Evasion):** Accuracy: 67.3%, Recall: 34.7%, F1 Score: 0.515
  - **Architectural Defense:** Progressive EWMA risk scoring + kernel cgroup isolation + non-destructive overlay rollback.

---

## Summary of Operator Actions

- **Investigate Alert:** Navigate to **Alerts & Forensics**, click on any alert row to view the full 11-feature snapshot and SHAP factor attribution.
- **Operator Override:** Click **"Release Process"** to unfreeze false positives or **"Confirm Threat"** to permanently terminate suspicious PIDs.
- **Tuning Settings:** Navigate to **System Settings** to calibrate EWMA alpha, adjust thresholds, edit protected allowlists, or click **"Reset Demo State"** to restore baseline files.
