"""
AdaptShield Model Registry
==========================
Manages versioned, metadata-rich machine learning models in models/registry/.

Each model directory contains:
- manifest.json: name, classifier_type, feature_columns, schema_version, data_source,
                 metrics, seed, git_commit, sha256, trained_at, active flag.
- model.joblib: serialized classifier object.

Enforces schema validation on model load and rejects incompatible models.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib

from adaptshield.classifier import (
    RuleBasedClassifier,
    SklearnClassifier,
    XGBClassifierWrapper,
    build_classifier,
)
from adaptshield.feature_aggregator import FEATURE_COLUMNS
from adaptshield.ml.schema import SCHEMA_VERSION, validate_features


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_current_git_commit() -> str:
    """Returns the current git commit hash, or 'unknown' if not available."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"


class ModelRegistry:
    def __init__(self, registry_dir: str | Path = "models/registry"):
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.overview_file = self.registry_dir / "registry_manifest.json"

    def register_model(
        self,
        name: str,
        classifier: Any,
        feature_columns: List[str] | None = None,
        data_source: str = "synthetic",
        metrics: Dict[str, Any] | None = None,
        seed: int = 42,
        active: bool = False,
        git_commit: str | None = None,
    ) -> Path:
        """
        Saves and registers a classifier in the registry with a complete manifest.
        """
        cols = list(feature_columns or FEATURE_COLUMNS)
        model_dir = self.registry_dir / name
        model_dir.mkdir(parents=True, exist_ok=True)

        model_file = model_dir / "model.joblib"
        classifier.save(str(model_file))
        sha256_hash = compute_file_sha256(model_file)

        # Detect classifier type
        if isinstance(classifier, RuleBasedClassifier):
            classifier_type = "rule_based"
        elif isinstance(classifier, SklearnClassifier):
            classifier_type = "random_forest"
        elif isinstance(classifier, XGBClassifierWrapper):
            classifier_type = "xgboost"
        else:
            classifier_type = getattr(classifier, "classifier_type", type(classifier).__name__)

        manifest: Dict[str, Any] = {
            "name": name,
            "classifier_type": classifier_type,
            "feature_columns": cols,
            "schema_version": SCHEMA_VERSION,
            "data_source": data_source,
            "metrics": metrics or {},
            "seed": seed,
            "git_commit": git_commit or get_current_git_commit(),
            "sha256": sha256_hash,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "active": active,
        }

        manifest_file = model_dir / "manifest.json"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        if active:
            self.set_active_model(name)

        self._update_overview()
        return model_dir

    def register_existing_joblib(
        self,
        name: str,
        joblib_path: Path | str,
        classifier_type: str,
        feature_columns: List[str] | None = None,
        data_source: str = "synthetic_bootstrap_legacy",
        metrics: Dict[str, Any] | None = None,
        seed: int = 0,
        active: bool = False,
    ) -> Path:
        """Registers a pre-existing joblib model artifact."""
        src_path = Path(joblib_path)
        if not src_path.exists():
            raise FileNotFoundError(f"Model file not found: {src_path}")

        cols = list(feature_columns or FEATURE_COLUMNS)
        model_dir = self.registry_dir / name
        model_dir.mkdir(parents=True, exist_ok=True)

        dst_file = model_dir / "model.joblib"
        shutil.copy2(src_path, dst_file)
        sha256_hash = compute_file_sha256(dst_file)

        manifest: Dict[str, Any] = {
            "name": name,
            "classifier_type": classifier_type,
            "feature_columns": cols,
            "schema_version": SCHEMA_VERSION,
            "data_source": data_source,
            "metrics": metrics or {},
            "seed": seed,
            "git_commit": get_current_git_commit(),
            "sha256": sha256_hash,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "active": active,
        }

        manifest_file = model_dir / "manifest.json"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        self._update_overview()
        return model_dir

    def load_model(
        self,
        name: str,
        expected_columns: List[str] | None = None,
    ) -> Tuple[Any, Dict[str, Any]]:
        """
        Loads a classifier and manifest by name.
        Rejects incompatible models (schema mismatch or missing columns).
        """
        model_dir = self.registry_dir / name
        manifest_file = model_dir / "manifest.json"
        model_file = model_dir / "model.joblib"

        if not manifest_file.exists() or not model_file.exists():
            raise FileNotFoundError(f"Model '{name}' not found in registry {self.registry_dir}")

        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Enforce schema version compatibility
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"Model '{name}' has incompatible schema version {manifest.get('schema_version')} "
                f"(current registry requires {SCHEMA_VERSION})"
            )

        # Enforce feature columns compatibility if expected_columns provided
        if expected_columns is not None:
            model_cols = manifest.get("feature_columns", [])
            if set(model_cols) != set(expected_columns):
                raise ValueError(
                    f"Model '{name}' is incompatible: column mismatch.\n"
                    f"Expected: {sorted(expected_columns)}\n"
                    f"Model has: {sorted(model_cols)}"
                )

        ctype = manifest.get("classifier_type", "xgboost")
        clf = build_classifier(ctype, columns=manifest.get("feature_columns"))
        clf.load(str(model_file))

        return clf, manifest

    def set_active_model(self, name: str) -> None:
        """Sets a registered model as active and deactivates all other models."""
        models = self.list_models()
        target_found = False

        for m in models:
            m_name = m["name"]
            m_manifest_path = self.registry_dir / m_name / "manifest.json"
            is_active = (m_name == name)
            if is_active:
                target_found = True
            m["active"] = is_active
            with open(m_manifest_path, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)

        if not target_found:
            raise ValueError(f"Cannot activate unknown model '{name}'")

        self._update_overview()

    def get_active_model(self) -> Tuple[Any, Dict[str, Any]]:
        """Returns the currently active classifier and its manifest."""
        models = self.list_models()
        active_manifest = next((m for m in models if m.get("active")), None)

        if not active_manifest:
            # Fall back to first available or raise
            if not models:
                raise RuntimeError("No models registered in registry")
            active_manifest = models[0]
            self.set_active_model(active_manifest["name"])

        return self.load_model(active_manifest["name"])

    def list_models(self) -> List[Dict[str, Any]]:
        """Lists all registered models manifests."""
        manifests = []
        if not self.registry_dir.exists():
            return manifests

        for d in sorted(self.registry_dir.iterdir()):
            if d.is_dir() and (d / "manifest.json").exists():
                with open(d / "manifest.json", "r", encoding="utf-8") as f:
                    try:
                        manifests.append(json.load(f))
                    except Exception:
                        pass
        return manifests

    def _update_overview(self) -> None:
        """Updates registry_manifest.json with the current list of all models."""
        models = self.list_models()
        active_name = next((m["name"] for m in models if m.get("active")), None)
        overview = {
            "schema_version": SCHEMA_VERSION,
            "total_models": len(models),
            "active_model": active_name,
            "models": models,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(self.overview_file, "w", encoding="utf-8") as f:
            json.dump(overview, f, indent=2)
