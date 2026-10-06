"""
Progressive risk assessment (roadmap Sec 2.3/2.4/8.1 ablation target #3).

Rationale: a single window's classifier output is noisy (a burst of
legitimate saves can momentarily look suspicious). AdaptShield accumulates
evidence with an exponentially-weighted moving average across consecutive
windows for the SAME pid, and only escalates the RISK LEVEL (as opposed to
the Tier-0->Tier-1 INSTRUMENTATION escalation, which is a separate, earlier
decision) once sustained evidence crosses thresholds.

Three levels, matching the roadmap's WATCH / SUSPECT / CRITICAL states.
Only CRITICAL triggers containment_manager.
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
        alpha: float = 0.4,          # EWMA smoothing factor (swept experimentally)
        watch_threshold: float = 0.3,
        suspect_threshold: float = 0.6,
        critical_threshold: float = 0.85,
        critical_confirm_windows: int = 2,  # require N consecutive windows
                                             # above critical_threshold before
                                             # actually declaring CRITICAL,
                                             # to reduce single-window false alarms
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
