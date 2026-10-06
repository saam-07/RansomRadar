"""
Root-level ml package compatibility alias
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from adaptshield.ml.schema import (
    FEATURE_COLUMNS,
    TIER0_COLUMNS,
    TIER1_COLUMNS,
    SCHEMA_VERSION,
    validate_features,
)
from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.train import train_classifier
from adaptshield.ml.evaluate import evaluate_classifier, replay_risk_scorer

__all__ = [
    "FEATURE_COLUMNS",
    "TIER0_COLUMNS",
    "TIER1_COLUMNS",
    "SCHEMA_VERSION",
    "validate_features",
    "ModelRegistry",
    "train_classifier",
    "evaluate_classifier",
    "replay_risk_scorer",
]
