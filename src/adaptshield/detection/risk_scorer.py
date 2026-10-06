"""
Progressive risk assessment with EWMA smoothing.
Accumulates suspicion evidence over consecutive windows per PID.
"""
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    NONE = 0
    WATCH = 1
    SUSPECT = 2
    CRITICAL = 3


@dataclass
class PidRiskState:
    ewma: float = 0.0
    level: RiskLevel = RiskLevel.NONE
    consecutive_above_critical: int = 0


class RiskScorer:
    def __init__(
        self,
        alpha: float = 0.4,
        watch_threshold: float = 0.3,
        suspect_threshold: float = 0.6,
        critical_threshold: float = 0.85,
        critical_confirm_windows: int = 2,
    ):
        self.alpha = alpha
        self.watch_threshold = watch_threshold
        self.suspect_threshold = suspect_threshold
        self.critical_threshold = critical_threshold
        self.critical_confirm_windows = critical_confirm_windows
        self._state: dict[int, PidRiskState] = {}

    def update(self, pid: int, p_ransomware: float) -> RiskLevel:
        st = self._state.setdefault(pid, PidRiskState())
        st.ewma = self.alpha * p_ransomware + (1 - self.alpha) * st.ewma

        if st.ewma >= self.critical_threshold:
            st.consecutive_above_critical += 1
        else:
            st.consecutive_above_critical = 0

        if st.consecutive_above_critical >= self.critical_confirm_windows:
            st.level = RiskLevel.CRITICAL
        elif st.ewma >= self.suspect_threshold:
            st.level = RiskLevel.SUSPECT
        elif st.ewma >= self.watch_threshold:
            st.level = RiskLevel.WATCH
        else:
            st.level = RiskLevel.NONE
        return st.level

    def get_ewma(self, pid: int) -> float:
        return self._state.get(pid, PidRiskState()).ewma

    def reset(self, pid: int):
        self._state.pop(pid, None)
