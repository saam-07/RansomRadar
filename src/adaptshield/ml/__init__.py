"""
AdaptShield ML Subsystem
"""
from adaptshield.ml.classifier import (
    RuleBasedClassifier,
    SklearnClassifier,
    XGBClassifierWrapper,
    build_classifier,
)
from adaptshield.ml.evaluate import evaluate_classifier, replay_risk_scorer
from adaptshield.ml.registry import ModelRegistry
from adaptshield.ml.schema import (
    FEATURE_COLUMNS,
    SCHEMA_VERSION,
    TIER0_COLUMNS,
    TIER1_COLUMNS,
    validate_features,
)
from adaptshield.ml.train import train_classifier

__all__ = [
    "FEATURE_COLUMNS",
    "SCHEMA_VERSION",
    "TIER0_COLUMNS",
    "TIER1_COLUMNS",
    "ModelRegistry",
    "RuleBasedClassifier",
    "SklearnClassifier",
    "XGBClassifierWrapper",
    "build_classifier",
    "evaluate_classifier",
    "replay_risk_scorer",
    "train_classifier",
    "validate_features",
]
