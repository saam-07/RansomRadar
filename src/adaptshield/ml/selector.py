"""
Classifier Auto-Selection & Synthetic Model Guard for AdaptShield.

Selects active model from the registry, validates feature compatibility,
enforces synthetic model safety rails, and guarantees safe fallback to RuleBasedClassifier.
NEVER crashes on a missing, corrupted, or incompatible model file.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Tuple

from ..config import AdaptShieldConfig
from ..logging.logger import get_logger
from .classifier import RuleBasedClassifier, build_classifier
from .schema import FEATURE_COLUMNS
from .registry import ModelRegistry

logger = get_logger("adaptshield.ml.selector")


def select_classifier(config: AdaptShieldConfig) -> Tuple[Any, Dict[str, Any]]:
    """
    Selects and validates the classifier to use based on configuration,
    model registry state, and synthetic guard rules.

    Returns:
        (classifier_instance, metadata_dict)
    """
    mode = getattr(config.classifier, "mode", "auto").lower()
    allow_synthetic = getattr(config.classifier, "allow_synthetic", False)
    operating_mode = getattr(config, "mode", "protect").lower()
    registry_dir = getattr(config.classifier, "registry_dir", "models/registry")

    # 1. Explicit rule_based mode
    if mode == "rule_based":
        logger.info("[CLASSIFIER] Operating in explicit rule_based heuristic mode.")
        return RuleBasedClassifier(), {
            "name": "rule_based",
            "classifier_type": "rule_based",
            "data_source": "heuristic",
            "synthetic": False,
            "synthetic_blocked": False,
            "fallback_used": False,
        }

    # 2. Check explicit model_path if configured
    model_path = getattr(config.classifier, "model_path", None)
    if model_path and os.path.exists(model_path):
        try:
            clf_name = getattr(config.classifier, "model_name", "xgboost")
            clf = build_classifier(clf_name).load(model_path)
            # Verify feature columns match
            if hasattr(clf, "feature_columns") and clf.feature_columns != FEATURE_COLUMNS:
                raise ValueError(
                    f"Model columns mismatch: {clf.feature_columns} != {FEATURE_COLUMNS}"
                )
            logger.info("[CLASSIFIER] Loaded model directly from model_path: %s", model_path)
            return clf, {
                "name": Path(model_path).stem,
                "classifier_type": clf_name,
                "data_source": "custom_path",
                "synthetic": False,
                "synthetic_blocked": False,
                "fallback_used": False,
            }
        except Exception as e:
            logger.warning(
                "[CLASSIFIER FALLBACK] Failed loading model from %s (%s). Falling back to registry / rule-based.",
                model_path,
                e,
            )

    # 3. Model Registry lookup
    if os.path.exists(registry_dir):
        try:
            registry = ModelRegistry(registry_dir)
            active_model, manifest = registry.get_active_model()
            model_name = manifest.get("name", "unknown")
            data_source = manifest.get("data_source", "real")
            is_synthetic = data_source == "synthetic"

            # Check column compatibility
            manifest_cols = manifest.get("feature_columns", [])
            if manifest_cols and manifest_cols != FEATURE_COLUMNS:
                logger.warning(
                    "[CLASSIFIER INCOMPATIBLE] Active model '%s' feature columns %s do not match schema %s. "
                    "Rejecting incompatible model and falling back to RuleBasedClassifier.",
                    model_name,
                    manifest_cols,
                    FEATURE_COLUMNS,
                )
                return RuleBasedClassifier(), {
                    "name": "rule_based",
                    "classifier_type": "rule_based",
                    "data_source": "heuristic",
                    "synthetic": False,
                    "synthetic_blocked": False,
                    "fallback_used": True,
                    "fallback_reason": f"Incompatible feature columns in '{model_name}'",
                }

            # Synthetic Guard:
            # Models with data_source=synthetic are NOT used for automatic containment
            # in protect mode unless classifier.allow_synthetic is explicitly true.
            if is_synthetic and operating_mode == "protect" and not allow_synthetic:
                logger.warning(
                    "[SYNTHETIC MODEL GUARD] Active model '%s' has data_source='synthetic'. "
                    "Automatic containment with synthetic model is BLOCKED in 'protect' mode. "
                    "Falling back to RuleBasedClassifier for containment. "
                    "Set classifier.allow_synthetic: true to override.",
                    model_name,
                )
                return RuleBasedClassifier(), {
                    "name": "rule_based",
                    "classifier_type": "rule_based",
                    "data_source": "synthetic_guarded_fallback",
                    "synthetic": True,
                    "synthetic_blocked": True,
                    "original_model": model_name,
                    "fallback_used": True,
                    "fallback_reason": "Synthetic model blocked in protect mode",
                }

            logger.info(
                "[CLASSIFIER] Successfully loaded active model '%s' (data_source=%s, synthetic=%s).",
                model_name,
                data_source,
                is_synthetic,
            )
            return active_model, {
                "name": model_name,
                "classifier_type": manifest.get("classifier_type", "xgboost"),
                "data_source": data_source,
                "synthetic": is_synthetic,
                "synthetic_blocked": False,
                "fallback_used": False,
            }

        except Exception as e:
            logger.warning(
                "[CLASSIFIER FALLBACK] Could not load active model from registry (%s). "
                "Falling back safely to RuleBasedClassifier. Never crashing.",
                e,
            )
            return RuleBasedClassifier(), {
                "name": "rule_based",
                "classifier_type": "rule_based",
                "data_source": "heuristic",
                "synthetic": False,
                "synthetic_blocked": False,
                "fallback_used": True,
                "fallback_reason": str(e),
            }

    # 4. Default fallback when no registry exists
    logger.warning(
        "[CLASSIFIER FALLBACK] No model registry found at '%s'. Falling back safely to RuleBasedClassifier.",
        registry_dir,
    )
    return RuleBasedClassifier(), {
        "name": "rule_based",
        "classifier_type": "rule_based",
        "data_source": "heuristic",
        "synthetic": False,
        "synthetic_blocked": False,
        "fallback_used": True,
        "fallback_reason": "Registry directory not found",
    }
