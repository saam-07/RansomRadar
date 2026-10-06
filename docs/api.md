# AdaptShield Backend REST & WebSocket API Reference

The AdaptShield backend exposes a high-performance REST and WebSocket API built with FastAPI and SQLite. It drives the Live Dashboard, Scenario Runner, Datasets Explorer, Models and Training interface, and Forensic Alert review.

- **Base URL:** `http://localhost:8000`
- **Interactive Documentation (Swagger / OpenAPI):** `http://localhost:8000/docs`
- **ReDoc Documentation:** `http://localhost:8000/redoc`
- **Provenance Rules:** All simulated responses return `"simulated": true`. All model responses include `"data_source"`.

---

## 1. Status & Control

### `GET /api/health`
Health check endpoint.
```bash
curl -s http://localhost:8000/api/health
```
**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "simulated": true
}
```

### `GET /api/status`
Returns runtime pipeline state, active detector, operating mode, policy, storm panic status, and active running scenario.
```bash
curl -s http://localhost:8000/api/status
```
**Response:**
```json
{
  "status": "running",
  "mode": "simulated",
  "active_policy": "immediate",
  "active_detector": "xgboost",
  "active_manifest": {
    "name": "xgboost",
    "classifier_type": "xgboost",
    "schema_version": "1.0.0",
    "data_source": "synthetic"
  },
  "data_source": "synthetic",
  "storm_panic": false,
  "running_scenario": null,
  "simulated": true
}
```

### `POST /api/control`
Modifies operating mode (`simulated` | `live`), response policy (`immediate` | `manual` | `none`), active detector, or resets the false-positive storm switch.
```bash
curl -X POST http://localhost:8000/api/control \
  -H "Content-Type: application/json" \
  -d '{"policy": "manual", "mode": "simulated"}'
```

---

## 2. Processes

### `GET /api/processes`
Returns the active processes tracked in the detection pipeline, their EWMA risk score, raw ransomware probability, freeze status, and file modification metrics.
```bash
curl -s http://localhost:8000/api/processes
```
**Response:**
```json
{
  "processes": [
    {
      "pid": 4099,
      "process_name": "locker_fast",
      "cmdline": "/usr/bin/locker_fast",
      "label": "ransomware",
      "risk_level": "CRITICAL",
      "ewma": 0.912,
      "probability": 0.9996,
      "status": "frozen",
      "is_frozen": true,
      "is_quarantined": true,
      "files_touched": 120,
      "files_encrypted": 55,
      "last_window_idx": 4,
      "simulated": true
    }
  ],
  "total": 1,
  "simulated": true
}
```

---

## 3. Alerts & Forensic Evidence

### `GET /api/alerts`
Lists forensic alerts with tree feature contributions / rule explanations and raw feature windows. Supports filtering by `run_id`, `risk_level`, and `status`.
```bash
curl -s "http://localhost:8000/api/alerts?limit=10"
```

### `GET /api/alerts/{alert_id}`
Retrieves detailed evidence for a specific alert.
```bash
curl -s http://localhost:8000/api/alerts/<ALERT_ID>
```

### `POST /api/containment/release`
Operator manual policy override: releases / unfreezes a contained process.
```bash
curl -X POST http://localhost:8000/api/containment/release \
  -H "Content-Type: application/json" \
  -d '{"pid": 4099, "action": "release", "reason": "Operator verified benign utility"}'
```

### `POST /api/containment/confirm`
Operator confirms threat: kills the malicious process and finalizes quarantine.
```bash
curl -X POST http://localhost:8000/api/containment/confirm \
  -H "Content-Type: application/json" \
  -d '{"pid": 4099, "action": "confirm", "reason": "Confirmed active encryptor"}'
```

---

## 4. Scenarios & Benchmark Runs

### `GET /api/scenarios`
Lists all available benchmark scenarios defined in `data/scenarios/`.
```bash
curl -s http://localhost:8000/api/scenarios
```

### `POST /api/scenarios/run`
Starts background execution of a scenario.
```bash
curl -X POST http://localhost:8000/api/scenarios/run \
  -H "Content-Type: application/json" \
  -d '{"scenario_name": "fast_ransomware", "detector": "xgboost", "policy": "immediate", "speed": 5.0, "seed": 42}'
```
**Response:**
```json
{
  "run_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "scenario_name": "fast_ransomware",
  "detector": "xgboost",
  "policy": "immediate",
  "speed": 5.0,
  "seed": 42,
  "status": "running",
  "message": "Scenario 'fast_ransomware' started successfully",
  "simulated": true
}
```

### `POST /api/scenarios/stop`
Stops the currently running scenario.
```bash
curl -X POST http://localhost:8000/api/scenarios/stop
```

### `GET /api/scenarios/runs`
Lists all recorded benchmark runs with summary metrics.
```bash
curl -s http://localhost:8000/api/scenarios/runs
```

### `GET /api/scenarios/runs/{run_id}`
Retrieves complete run details, including detection latency, files encrypted vs restored, and filesystem status.
```bash
curl -s http://localhost:8000/api/scenarios/runs/<RUN_ID>
```

---

## 5. Datasets

### `GET /api/datasets`
Returns dataset manifest, schema version (`1.0.0`), split checksums, and row counts.
```bash
curl -s http://localhost:8000/api/datasets
```

### `GET /api/datasets/{split}/sample`
Returns sample rows from a split (`train`, `val`, `test`, `hard_test`).
```bash
curl -s "http://localhost:8000/api/datasets/test/sample?limit=5"
```

### `GET /api/datasets/{split}/stats`
Returns summary statistics per feature per class.
```bash
curl -s http://localhost:8000/api/datasets/test/stats
```

### `POST /api/datasets/generate`
Triggers generation of new benchmark datasets with fixed seed.
```bash
curl -X POST http://localhost:8000/api/datasets/generate \
  -H "Content-Type: application/json" \
  -d '{"seed": 42, "imbalanced": false}'
```

---

## 6. Models & Registry

### `GET /api/models`
Lists all registered models in `models/registry/`.
```bash
curl -s http://localhost:8000/api/models
```

### `GET /api/models/{model_name}/evaluation`
Returns complete evaluation metrics for a model (confusion matrix, ROC & PR points, per-scenario family breakdown, hard-test results).
```bash
curl -s http://localhost:8000/api/models/xgboost/evaluation
```

### `POST /api/models/activate`
Activates a registered model with schema and column compatibility verification. **Rejects incompatible models with HTTP 400.**
```bash
curl -X POST http://localhost:8000/api/models/activate \
  -H "Content-Type: application/json" \
  -d '{"model_name": "random_forest"}'
```

### `POST /api/models/train`
Triggers a background model training job.
```bash
curl -X POST http://localhost:8000/api/models/train \
  -H "Content-Type: application/json" \
  -d '{"classifier_type": "xgboost", "model_name": "xgb_retrained", "hyperparameters": {"n_estimators": 50, "max_depth": 4}}'
```

### `GET /api/models/training/{job_id}`
Checks training job progress and status.
```bash
curl -s http://localhost:8000/api/models/training/<JOB_ID>
```

### `POST /api/models/predict`
Ad-hoc inference endpoint for the interactive "Try It" slider widget. Validates input schema and returns class probabilities and feature importance explanations.
```bash
curl -X POST http://localhost:8000/api/models/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "mod_rate": 85.0,
      "rename_rate": 40.0,
      "create_del_rate": 4.0,
      "event_count": 130.0,
      "concentration_gini": 0.75,
      "t1_write_rate": 80.0,
      "t1_mean_entropy": 7.85,
      "t1_entropy_std": 0.22,
      "t1_unlink_rate": 3.0,
      "t1_rename_rate": 38.0,
      "t1_mean_write_size": 4096.0
    }
  }'
```

---

## 7. WebSocket Stream (`/api/stream`)

Connect to `ws://localhost:8000/api/stream` to receive batched real-time telemetry events.

### Message Types
1. `connection_established`: Sent immediately upon connection.
2. `window_scored`: Real-time score for an evaluated process window.
3. `alert`: Critical alert generated with forensic attribution.
4. `containment`: Process freeze, quarantine, rollback, release, or kill.
5. `scenario_state`: Started, running, stopped, or completed scenario notifications.
6. `panic_switch`: False-positive storm panic switch notification.

### Batch Format
To avoid flooding browsers at high simulation speeds (e.g. 20x), messages are grouped into batched arrays flushed every ~80ms:
```json
{
  "type": "batch",
  "count": 2,
  "events": [
    {
      "type": "window_scored",
      "data": {
        "pid": 4099,
        "process_name": "locker_fast",
        "window_idx": 3,
        "probability": 0.985,
        "ewma": 0.812,
        "risk_level": "CRITICAL"
      },
      "simulated": true
    },
    {
      "type": "containment",
      "data": {
        "pid": 4099,
        "action": "freeze",
        "is_frozen": true,
        "latency_ms": 1.2
      },
      "simulated": true
    }
  ],
  "simulated": true
}
```

Clients can also send `{"type": "ping"}` and receive `{"type": "pong", "simulated": true}` for connection health checks.

---

## 8. Settings & Runtime Configuration

### `GET /api/settings`
Retrieves engine parameters ($\theta_0$, window size, EWMA $\alpha$, risk thresholds, allowlist, and policy).
```bash
curl -s http://localhost:8000/api/settings
```

### `POST /api/settings`
Updates runtime parameters and immediately propagates them to active scorers and safety rails.
```bash
curl -X POST http://localhost:8000/api/settings \
  -H "Content-Type: application/json" \
  -d '{"ewma_alpha": 0.5, "critical_threshold": 0.80, "policy": "immediate"}'
```

### `POST /api/settings/reset`
Resets all simulator files back to 300 intact files, clears active scenarios, resets panic storm switch, and reseeds initial demo run history.
```bash
curl -X POST http://localhost:8000/api/settings/reset
```

