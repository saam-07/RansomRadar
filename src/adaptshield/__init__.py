"""
AdaptShield -- Autonomous Linux Ransomware Detection & Reversible Containment System.
"""
__version__ = "0.2.0"

from .config import AdaptShieldConfig, load_config
from .daemon import AdaptShieldDaemon
from .detection.fanotify_ctypes import Fanotify, FanotifyEvent
from .detection.feature_aggregator import (
    FEATURE_COLUMNS,
    FeatureAggregator,
    build_feature_row,
)
from .detection.risk_scorer import RiskLevel, RiskScorer
from .detection.tier0_watcher import Tier0Watcher, tier0_suspicion_score
from .detection.tier1_bridge import Tier1Tracer, get_tier1_status, is_tier1_available
from .logging.alert_logger import AlertLogger
from .logging.logger import get_logger, setup_logging
from .ml.classifier import build_classifier
from .ml.explain import explain_alert
from .ml.registry import ModelRegistry
from .ml.selector import select_classifier
from .mode import ModeManager
from .response.containment_manager import (
    ContainmentManager,
    ContainmentResult,
    RollbackPolicy,
    contain,
    freeze_pid,
    kill_pid,
    unfreeze_pid,
)
from .response.protection import ProtectionManager, ProtectionTarget
from .response.safety import SafetyRails
from .state import StateManager
from .telemetry import TelemetryWriter

__all__ = [
    "FEATURE_COLUMNS",
    "AdaptShieldConfig",
    "AdaptShieldDaemon",
    "AlertLogger",
    "ContainmentManager",
    "ContainmentResult",
    "Fanotify",
    "FanotifyEvent",
    "FeatureAggregator",
    "ModeManager",
    "ModelRegistry",
    "ProtectionManager",
    "ProtectionTarget",
    "RiskLevel",
    "RiskScorer",
    "RollbackPolicy",
    "SafetyRails",
    "StateManager",
    "TelemetryWriter",
    "Tier0Watcher",
    "Tier1Tracer",
    "__version__",
    "build_classifier",
    "build_feature_row",
    "contain",
    "explain_alert",
    "freeze_pid",
    "get_logger",
    "get_tier1_status",
    "is_tier1_available",
    "kill_pid",
    "load_config",
    "select_classifier",
    "setup_logging",
    "tier0_suspicion_score",
    "unfreeze_pid",
]
