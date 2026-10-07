# AdaptShield Machine Learning Integration & Model Seam Specification

## 1. Overview & Architectural Seam

AdaptShield employs a clean decoupled seam between detection mechanics (filesystem fanotify streaming, eBPF kprobes, cgroup containment) and machine learning inference. Machine learning models predict the instantaneous probability of ransomware behavior based on an 11-feature temporal snapshot.

The architecture is explicitly designed for continuous evolution: security operators and researchers can train new models offline, validate them against the schema contract, and deploy them atomically into running production agents with zero downtime.

---

## 2. Canonical Feature Schema Contract (`v1.0.0`)

All models adhere to the canonical schema defined in [`src/adaptshield/ml/schema.py`](file:///src/adaptshield/ml/schema.py):

| Index | Feature Identifier | Tier | Unit / Scale | Description |
|---|---|:---:|---|---|
| 0 | `mod_rate` | Tier-0 | events / sec | File modification event rate over the sliding window |
| 1 | `rename_rate` | Tier-0 | events / sec | File rename/move rate |
| 2 | `create_del_rate` | Tier-0 | events / sec | Aggregated creation and deletion rate |
| 3 | `event_count` | Tier-0 | count | Total raw filesystem events in sliding window |
| 4 | `concentration_gini` | Tier-0 | $[0, 1]$ | Gini inequality coefficient across targeted directory paths |
| 5 | `t1_write_rate` | Tier-1 | syscalls / sec | Kernel `sys_enter_write` invocation rate (via eBPF) |
| 6 | `t1_mean_entropy` | Tier-1 | $[0, 8]$ bits/byte | Shannon entropy of write buffers observed in kernel space |
| 7 | `t1_entropy_std` | Tier-1 | bits/byte | Standard deviation of write buffer entropy |
| 8 | `t1_unlink_rate` | Tier-1 | syscalls / sec | Kernel `sys_enter_unlinkat` deletion rate |
| 9 | `t1_rename_rate` | Tier-1 | syscalls / sec | Kernel `sys_enter_renameat2` invocation rate |
| 10 | `t1_mean_write_size` | Tier-1 | bytes | Mean write buffer payload size |

### Input Validation & NaN Semantics
Prior to inference, inputs pass through `validate_features()`:
- Non-feature metadata (`pid`, `label`, `timestamp`, `scenario`) are stripped.
- Canonical feature ordering is strictly enforced.
- **Graceful NaN Handling:** When Tier-1 eBPF tracing is unescalated or unavailable on the host kernel, Tier-1 columns evaluate to `NaN` (or `-1.0` if configured). Tree models natively partition `NaN` values without errors.

---

## 3. Classifier Protocol & Plugin Interface

Any model conforming to the following protocol can be plugged in:

```python
class Classifier(Protocol):
    columns: list[str]

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Returns ndarray of shape (n_samples, n_classes)."""
        ...

    def save(self, path: str) -> None:
        ...

    @classmethod
    def load(cls, path: str) -> "Classifier":
        ...
```

Supported out-of-the-box classifiers:
- `RuleBasedClassifier`: deterministic multi-condition heuristic with zero external dependencies.
- `SklearnClassifier`: Random Forest ensemble (`scikit-learn`).
- `XGBClassifierWrapper`: Gradient boosted decision trees (`xgboost`).

---

## 4. Model Registry & Metadata Manifest

Production models reside in `/var/lib/adaptshield/models/` (or repository `models/registry/`) accompanied by `registry_manifest.json`:

```json
{
  "id": "model_xgb_v2",
  "name": "xgboost",
  "classifier_type": "xgboost",
  "data_source": "real",
  "active": true,
  "feature_schema_version": "1.0.0",
  "feature_columns": [
    "mod_rate", "rename_rate", "create_del_rate", "event_count", "concentration_gini",
    "t1_write_rate", "t1_mean_entropy", "t1_entropy_std", "t1_unlink_rate", "t1_rename_rate", "t1_mean_write_size"
  ],
  "metrics": {
    "test_accuracy": 0.985,
    "hard_test_recall": 0.347
  },
  "sha256": "4b68ef97...",
  "trained_at": "2026-10-06T14:55:07Z"
}
```

A symbolic link `/var/lib/adaptshield/models/current` points to the active model artifact.

---

## 5. Startup Classifier Selection & Synthetic Guard

When the agent starts with `classifier.mode: auto`:
1. It queries the model registry for the active model.
2. It verifies the artifact's SHA256 integrity and checks that `feature_columns` match `FEATURE_COLUMNS`.
3. **Synthetic-Model Guard:** Models tagged with `"data_source": "synthetic"` cannot be used for automated containment in `protect` mode unless `classifier.allow_synthetic: true` is explicitly configured. If `allow_synthetic` is `false`, the agent automatically selects `RuleBasedClassifier` for protection and outputs a warning. Synthetic models are permitted in `monitor` and `learn` modes.
4. **Zero-Crash Resilience:** If registry loading fails or the model artifact is missing or corrupted, the agent logs an alert and falls back to `RuleBasedClassifier`. The daemon never crashes due to a bad model file.

---

## 6. Hot Reloading & Model Rollback

To deploy a new model without interrupting daemon operations:

```bash
# 1. Inspect existing active model
adaptshield model info

# 2. Hot-reload model from registry (or send SIGHUP to agent PID)
adaptshield model reload
# OR: sudo kill -HUP $(pgrep -f adaptshield-agent)

# 3. Rollback to previously active model if anomalies occur
adaptshield model rollback
```

If validation of the replacement model fails during hot reload, the agent retains the running model and logs the rejection error.

---

## 7. Explainable Alerts

Alert records emitted by the agent include a dedicated `explanation` block explaining why a decision was reached:
- **Heuristic Classifier:** Lists the specific thresholds triggered (e.g. `fired_rules: ["mod_rate >= 80.0", "rename_rate >= 30.0"]`).
- **Tree Ensembles (RF / XGBoost):** Computes top feature importances and contributions (e.g. `t1_mean_entropy` contributed 42%, `mod_rate` contributed 28%).

---

## 8. Flight Telemetry Data Flywheel

The agent can continuously stream unlabeled feature vectors, risk scores, and containment actions to `/var/lib/adaptshield/telemetry/`:
- Automatic log rotation (default 50 MB cap per file).
- Records real host execution traces without impacting detection latency.
- Training pipeline: `adaptshield train --data /var/lib/adaptshield/telemetry` reads collected flight telemetry for model retraining.
