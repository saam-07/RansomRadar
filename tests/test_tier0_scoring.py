from adaptshield.tier0_watcher import gini_of_gaps, tier0_suspicion_score


def test_gini_uniform_spacing_is_low():
    timestamps = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
    g = gini_of_gaps(timestamps)
    assert g < 0.05


def test_gini_bursty_spacing_is_high():
    # nine events almost simultaneous, then one long gap
    timestamps = [0.0, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 10.0]
    g = gini_of_gaps(timestamps)
    assert g > 0.5


def test_suspicion_score_benign_is_low():
    feats = {"mod_rate": 0.5, "rename_rate": 0.0, "create_del_rate": 0.1,
              "concentration_gini": 0.1}
    score = tier0_suspicion_score(feats)
    assert score < 0.2


def test_suspicion_score_ransomware_like_is_high():
    feats = {"mod_rate": 60.0, "rename_rate": 40.0, "create_del_rate": 10.0,
              "concentration_gini": 0.8}
    score = tier0_suspicion_score(feats)
    assert score > 0.7
