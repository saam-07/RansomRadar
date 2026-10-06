"""
AdaptShield Forensic Alert Explanations Module.
Generates human-interpretable forensic attributions for high-risk alerts:
- Rule-based: identifies which specific threshold fired.
- Tree models: computes per-feature risk contributions based on weights and anomalies.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from .classifier import RuleBasedClassifier

FEATURE_NARRATIVES = {
    "t1_mean_entropy": "High write byte entropy ({val:.2f}) indicates encrypted or compressed payload",
    "concentration_gini": "Elevated directory concentration ({val:.2f}) reflects localized directory traversal",
    "rename_rate": "Rapid file rename activity ({val:.2f}/sec) matches extension-altering encryptor behavior",
    "t1_rename_rate": "eBPF syscall telemetry confirms accelerated file rename operations ({val:.2f}/sec)",
    "mod_rate": "High modification volume ({val:.2f} events/sec) suggests bulk overwrites",
    "t1_write_rate": "eBPF write rate ({val:.2f}/sec) reflects continuous file payload modification",
    "create_del_rate": "High file deletion rate ({val:.2f}/sec) indicates original files being wiped",
    "t1_unlink_rate": "Low-level sys_unlink calls ({val:.2f}/sec) indicate ransomware clone-and-delete pattern",
}


def explain_alert(
    classifier: Any,
    feature_row: dict[str, Any] | pd.Series,
    classifier_name: str = "xgboost",
) -> dict[str, Any]:
    """
    Produces an explanation for a high-risk alert.
    """
    row_dict = dict(feature_row)

    # 1. Rule-based explanation
    if isinstance(classifier, RuleBasedClassifier) or classifier_name == "rule_based":
        mod = float(row_dict.get("mod_rate", 0.0) or 0.0)
        ren = float(row_dict.get("rename_rate", 0.0) or 0.0)
        fired_rules = []
        if mod >= 80.0:
            fired_rules.append(f"Modification rate ({mod:.1f}/sec) >= 80.0 threshold")
        if ren >= 30.0:
            fired_rules.append(f"Rename rate ({ren:.1f}/sec) >= 30.0 threshold")

        summary = " and ".join(fired_rules) if fired_rules else "Elevated aggregate activity rates"
        return {
            "type": "rule_based",
            "summary": summary,
            "fired_rules": fired_rules,
            "contributions": [
                {"feature": "mod_rate", "value": mod, "threshold": 80.0, "fired": mod >= 80.0},
                {"feature": "rename_rate", "value": ren, "threshold": 30.0, "fired": ren >= 30.0},
            ],
        }

    # 2. Tree-based explanation (XGBoost / Random Forest)
    contributions: list[dict[str, Any]] = []

    # Get feature importances if available
    importances: dict[str, float] = {}
    if hasattr(classifier, "model") and hasattr(classifier.model, "feature_importances_"):
        cols = getattr(classifier, "columns", list(row_dict.keys()))
        imps = classifier.model.feature_importances_
        importances = {c: float(v) for c, v in zip(cols, imps)}

    # Reference baseline means for non-ransomware traffic
    benchmarks = {
        "t1_mean_entropy": (4.2, 7.0),
        "concentration_gini": (0.25, 0.50),
        "rename_rate": (1.0, 15.0),
        "t1_rename_rate": (0.8, 12.0),
        "mod_rate": (20.0, 45.0),
        "t1_unlink_rate": (0.5, 10.0),
        "create_del_rate": (2.0, 12.0),
    }

    for feat, (bench_mean, susp_thresh) in benchmarks.items():
        val = row_dict.get(feat)
        if val is not None and not (isinstance(val, float) and np.isnan(val)):
            try:
                fval = float(val)
            except (ValueError, TypeError):
                continue
            weight = float(importances.get(feat, 0.1))

            if fval >= susp_thresh:
                score = round(float(weight * (1.0 + (fval - susp_thresh) / susp_thresh)), 4)
                narrative_tmpl = FEATURE_NARRATIVES.get(feat, "{val:.2f} elevated")
                contributions.append({
                    "feature": feat,
                    "value": round(fval, 3),
                    "importance_weight": round(weight, 3),
                    "contribution_score": score,
                    "narrative": narrative_tmpl.format(val=fval),
                })

    # Sort descending by contribution score
    contributions.sort(key=lambda x: x["contribution_score"], reverse=True)
    summary = (
        f"Top anomaly: {contributions[0]['narrative']}"
        if contributions
        else "Statistical profile matched trained ransomware parameters"
    )

    return {
        "type": "tree_importance",
        "summary": summary,
        "fired_rules": [c["narrative"] for c in contributions[:3]],
        "contributions": contributions,
    }
