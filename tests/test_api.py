"""
AdaptShield Backend API & WebSocket Test Suite.
Verifies API contracts, WebSocket stream, training job lifecycle,
and model activation compatibility checks.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from adaptshield.ml.schema import FEATURE_COLUMNS
from adaptshield.ml.registry import ModelRegistry


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


# 1. Health and Status Tests
def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["simulated"] is True


def test_status_endpoint(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] in ("simulated", "live")
    assert data["active_policy"] in ("immediate", "manual", "none")
    assert "active_detector" in data
    assert data["simulated"] is True
    assert "data_source" in data


def test_control_endpoint(client):
    res = client.post("/api/control", json={"policy": "manual", "mode": "simulated"})
    assert res.status_code == 200
    data = res.json()
    assert data["policy"] == "manual"
    assert data["simulated"] is True

    # Revert to immediate
    res2 = client.post("/api/control", json={"policy": "immediate"})
    assert res2.status_code == 200
    assert res2.json()["policy"] == "immediate"


# 2. Processes Endpoint Tests
def test_processes_endpoint(client):
    res = client.get("/api/processes")
    assert res.status_code == 200
    data = res.json()
    assert "processes" in data
    assert data["simulated"] is True


# 3. Alerts and Containment Action Tests
def test_alerts_endpoint_and_detail(client):
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert data["simulated"] is True
    assert len(data["alerts"]) > 0  # auto-seeded

    first_alert = data["alerts"][0]
    alert_id = first_alert["id"]

    res_detail = client.get(f"/api/alerts/{alert_id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["id"] == alert_id
    assert "explanation" in detail
    assert detail["simulated"] is True


def test_containment_release_and_confirm(client):
    # Test release
    res_rel = client.post("/api/containment/release", json={"pid": 4099, "action": "release"})
    assert res_rel.status_code == 200
    assert res_rel.json()["action"] == "release"
    assert res_rel.json()["simulated"] is True

    # Test confirm
    res_conf = client.post("/api/containment/confirm", json={"pid": 4099, "action": "confirm"})
    assert res_conf.status_code == 200
    assert res_conf.json()["action"] == "confirm"
    assert res_conf.json()["simulated"] is True


# 4. Scenarios Tests
def test_scenarios_listing(client):
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 8
    scen_ids = [s["id"] for s in data]
    assert "fast_ransomware" in scen_ids
    assert "nightly_backup" in scen_ids


def test_scenario_run_and_history(client):
    # Run scenario with high speed for test
    res = client.post("/api/scenarios/run", json={
        "scenario_name": "normal_workday",
        "speed": 50.0,
        "seed": 42,
    })
    assert res.status_code == 200
    run_data = res.json()
    run_id = run_data["run_id"]
    assert run_data["status"] == "running"
    assert run_data["simulated"] is True

    # Check runs listing
    res_runs = client.get("/api/scenarios/runs")
    assert res_runs.status_code == 200
    runs = res_runs.json()
    assert len(runs) > 0

    # Check run detail
    res_detail = client.get(f"/api/scenarios/runs/{run_id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == run_id


# 5. Datasets Tests
def test_datasets_overview_and_samples(client):
    res = client.get("/api/datasets")
    assert res.status_code == 200
    data = res.json()
    assert data["schema_version"] == "1.0.0"
    assert "splits" in data["files"] or "train" in data["files"]
    assert data["simulated"] is True

    # Sample rows from test
    res_sample = client.get("/api/datasets/test/sample?limit=5")
    assert res_sample.status_code == 200
    sample_data = res_sample.json()
    assert sample_data["split"] == "test"
    assert len(sample_data["rows"]) == 5
    assert sample_data["simulated"] is True

    # Stats for test
    res_stats = client.get("/api/datasets/test/stats")
    assert res_stats.status_code == 200
    stats_data = res_stats.json()
    assert "class_distribution" in stats_data
    assert "feature_statistics" in stats_data
    assert stats_data["simulated"] is True


# 6. Models Tests
def test_models_listing_and_evaluation(client):
    res = client.get("/api/models")
    assert res.status_code == 200
    data = res.json()
    assert len(data["models"]) >= 4
    assert data["data_source"] == "synthetic"
    assert data["simulated"] is True

    # Evaluation metrics
    res_eval = client.get("/api/models/xgboost/evaluation")
    assert res_eval.status_code == 200
    eval_data = res_eval.json()
    assert "metrics" in eval_data
    assert eval_data["data_source"] == "synthetic"
    assert eval_data["simulated"] is True


def test_model_predict(client):
    # Valid feature row
    valid_features = {
        "mod_rate": 80.0,
        "rename_rate": 35.0,
        "create_del_rate": 3.0,
        "event_count": 120.0,
        "concentration_gini": 0.72,
        "t1_write_rate": 70.0,
        "t1_mean_entropy": 7.8,
        "t1_entropy_std": 0.2,
        "t1_unlink_rate": 2.0,
        "t1_rename_rate": 30.0,
        "t1_mean_write_size": 4096.0,
    }
    res = client.post("/api/models/predict", json={"features": valid_features})
    assert res.status_code == 200
    pred = res.json()
    assert pred["prediction"] in ("ransomware", "benign")
    assert "probability_ransomware" in pred
    assert "explanation" in pred
    assert pred["data_source"] == "synthetic"
    assert pred["simulated"] is True


def test_model_activation_compatibility_check(client, tmp_path):
    # 1. Compatible activation succeeds
    res_act = client.post("/api/models/activate", json={"model_name": "random_forest"})
    assert res_act.status_code == 200
    assert res_act.json()["active_model"] == "random_forest"

    # Reactivate xgboost
    res_xgb = client.post("/api/models/activate", json={"model_name": "xgboost"})
    assert res_xgb.status_code == 200

    # 2. Non-existent model fails with 404
    res_none = client.post("/api/models/activate", json={"model_name": "ghost_model_xyz"})
    assert res_none.status_code == 404

    # 3. Create an incompatible model with mismatched schema version in registry
    registry = ModelRegistry()
    incompat_dir = registry.registry_dir / "incompatible_test_model"
    incompat_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": "incompatible_test_model",
        "classifier_type": "random_forest",
        "schema_version": "0.0.1_legacy_broken",
        "feature_columns": ["wrong_col1", "wrong_col2"],
        "data_source": "synthetic",
        "active": False,
    }
    with open(incompat_dir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    # Dummy model file
    with open(incompat_dir / "model.joblib", "wb") as f:
        f.write(b"dummy")

    try:
        # Activation MUST be rejected!
        res_incompat = client.post("/api/models/activate", json={"model_name": "incompatible_test_model"})
        assert res_incompat.status_code == 400
        assert "incompatible" in res_incompat.json()["detail"].lower()
    finally:
        import shutil
        shutil.rmtree(incompat_dir, ignore_errors=True)


def test_training_job_lifecycle(client):
    # Queue a training job
    res = client.post("/api/models/train", json={
        "classifier_type": "random_forest",
        "model_name": "test_rf_job",
        "hyperparameters": {"n_estimators": 5, "max_depth": 3},
    })
    assert res.status_code == 200
    job_data = res.json()
    job_id = job_data["job_id"]
    assert job_data["status"] == "queued"
    assert job_data["simulated"] is True

    # Poll status
    res_status = client.get(f"/api/models/training/{job_id}")
    assert res_status.status_code == 200
    st = res_status.json()
    assert st["job_id"] == job_id
    assert st["status"] in ("queued", "running", "completed")
    assert st["simulated"] is True

    import shutil
    registry = ModelRegistry()
    shutil.rmtree(registry.registry_dir / "test_rf_job", ignore_errors=True)


# 7. WebSocket Stream Test
def test_websocket_stream(client):
    with client.websocket_connect("/api/stream") as websocket:
        # First message should be connection acknowledgment
        init_data = websocket.receive_text()
        msg = json.loads(init_data)
        assert msg["type"] == "connection_established"
        assert msg["simulated"] is True

        # Send ping
        websocket.send_text(json.dumps({"type": "ping"}))
        pong_data = websocket.receive_text()
        pong_msg = json.loads(pong_data)
        assert pong_msg["type"] == "pong"
        assert pong_msg["simulated"] is True
