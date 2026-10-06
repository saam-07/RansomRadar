"""
AdaptShield ML Subsystem
"""
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
from adaptshield.ml.classifier import (
    build_classifier,
    RuleBasedClassifier,
    SklearnClassifier,
    XGBClassifierWrapper,
)

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
    "build_classifier",
    "RuleBasedClassifier",
    "SklearnClassifier",
    "XGBClassifierWrapper",
]
