"""
AdaptShield -- Autonomous Linux Ransomware Detection & Reversible Containment System.
"""
__version__ = "0.2.0"

from .config import AdaptShieldConfig, load_config
from .daemon import AdaptShieldDaemon
from .detection.fanotify_ctypes import Fanotify, FanotifyEvent
from .detection.tier0_watcher import Tier0Watcher, tier0_suspicion_score
from .detection.tier1_bridge import Tier1Tracer, is_tier1_available, get_tier1_status
from .detection.feature_aggregator import FeatureAggregator, FEATURE_COLUMNS, build_feature_row
from .detection.risk_scorer import RiskScorer, RiskLevel
from .response.containment_manager import (
    ContainmentManager,
    ContainmentResult,
    RollbackPolicy,
    contain,
    freeze_pid,
    unfreeze_pid,
    kill_pid,
)
from .logging.logger import setup_logging, get_logger
from .logging.alert_logger import AlertLogger
from .ml.registry import ModelRegistry
from .ml.classifier import build_classifier

__all__ = [
    "__version__",
    "AdaptShieldConfig",
    "load_config",
    "AdaptShieldDaemon",
    "Fanotify",
    "FanotifyEvent",
    "Tier0Watcher",
    "tier0_suspicion_score",
    "Tier1Tracer",
    "is_tier1_available",
    "get_tier1_status",
    "FeatureAggregator",
    "FEATURE_COLUMNS",
    "build_feature_row",
    "RiskScorer",
    "RiskLevel",
    "ContainmentManager",
    "ContainmentResult",
    "RollbackPolicy",
    "contain",
    "freeze_pid",
    "unfreeze_pid",
    "kill_pid",
    "setup_logging",
    "get_logger",
    "AlertLogger",
    "ModelRegistry",
    "build_classifier",
]
