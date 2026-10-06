from adaptshield.risk_scorer import RiskLevel, RiskScorer


def test_low_probability_stays_none():
    rs = RiskScorer()
    for _ in range(5):
        level = rs.update(pid=1, p_ransomware=0.05)
    assert level == RiskLevel.NONE


def test_sustained_high_probability_reaches_critical():
    # NOTE: with the default alpha=0.4, the EWMA takes several windows of
    # sustained p=0.95 to climb above critical_threshold=0.85 -- this is
    # expected (progressive risk assessment is deliberately not instant on
    # a single strong window). Run enough windows for the EWMA to actually
    # converge, then require critical_confirm_windows of confirmation.
    rs = RiskScorer(critical_confirm_windows=2)
    level = RiskLevel.NONE
    for _ in range(10):
        level = rs.update(pid=1, p_ransomware=0.95)
    assert level == RiskLevel.CRITICAL
    assert rs.get_ewma(1) > 0.85


def test_single_spike_does_not_immediately_trigger_critical():
    rs = RiskScorer(alpha=0.3, critical_confirm_windows=3)
    for _ in range(3):
        rs.update(pid=1, p_ransomware=0.0)
    level = rs.update(pid=1, p_ransomware=1.0)  # one spike
    assert level != RiskLevel.CRITICAL


def test_pids_are_independent():
    rs = RiskScorer()
    rs.update(pid=1, p_ransomware=0.95)
    rs.update(pid=1, p_ransomware=0.95)
    level_pid2 = rs.update(pid=2, p_ransomware=0.0)
    assert level_pid2 == RiskLevel.NONE
