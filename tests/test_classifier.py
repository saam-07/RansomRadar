import pandas as pd

from adaptshield.classifier import build_classifier
from adaptshield.feature_aggregator import FEATURE_COLUMNS


def test_rule_based_classifier():
    clf = build_classifier("rule_based")
    df = pd.DataFrame([{
        "mod_rate": 90.0,
        "rename_rate": 40.0,
        "create_del_rate": 10.0,
        "event_count": 50,
        "concentration_gini": 0.8,
    }])
    proba = clf.predict_proba(df)
    assert proba.shape == (1, 2)
    assert proba[0, 1] == 1.0  # both thresholds exceeded


def test_classifier_save_load_sklearn(tmp_path):
    clf = build_classifier("random_forest")
    # Make small dummy dataset
    X = pd.DataFrame([{c: 1.0 for c in FEATURE_COLUMNS} for _ in range(10)])
    y = pd.Series(["benign"] * 5 + ["ransomware"] * 5)
    clf.fit(X, y)

    save_path = str(tmp_path / "rf_test.joblib")
    clf.save(save_path)

    loaded = build_classifier("random_forest").load(save_path)
    proba = loaded.predict_proba(X)
    assert proba.shape[0] == 10


def test_classifier_save_load_xgboost(tmp_path):
    clf = build_classifier("xgboost")
    X = pd.DataFrame([{c: 1.0 for c in FEATURE_COLUMNS} for _ in range(10)])
    y = pd.Series(["benign"] * 5 + ["ransomware"] * 5)
    clf.fit(X, y)

    save_path = str(tmp_path / "xgb_test.joblib")
    clf.save(save_path)

    loaded = build_classifier("xgboost").load(save_path)
    proba = loaded.predict_proba(X)
    assert proba.shape[0] == 10
