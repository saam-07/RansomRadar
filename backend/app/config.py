"""
Configuration management for AdaptShield Backend.
Loads settings from YAML, environment variables, or defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List
import yaml
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "backend" / "config.yaml"


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])


class DatabaseConfig(BaseModel):
    url: str = f"sqlite:///{REPO_ROOT / 'data' / 'adaptshield.db'}"


class PipelineConfig(BaseModel):
    default_detector: str = "xgboost"
    default_policy: str = "immediate"  # immediate | manual | none
    default_mode: str = "simulated"    # simulated | live
    ewma_alpha: float = 0.4
    critical_confirm_windows: int = 2
    panic_storm_threshold: int = 5


class FeaturesConfig(BaseModel):
    live_agent_source_enabled: bool = False
    real_containment_enabled: bool = False


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)


def load_config(config_path: Path | str | None = None) -> AppConfig:
    """Loads configuration with fallback to defaults."""
    target_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    raw: Dict[str, Any] = {}
    if target_path.exists():
        with open(target_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    # Allow environment variable overrides
    if "ADAPTSHIELD_DB_URL" in os.environ:
        raw.setdefault("database", {})["url"] = os.environ["ADAPTSHIELD_DB_URL"]

    if "ADAPTSHIELD_DETECTOR" in os.environ:
        raw.setdefault("pipeline", {})["default_detector"] = os.environ["ADAPTSHIELD_DETECTOR"]

    if "ADAPTSHIELD_POLICY" in os.environ:
        raw.setdefault("pipeline", {})["default_policy"] = os.environ["ADAPTSHIELD_POLICY"]

    return AppConfig(**raw)


# Global singleton instance
settings = load_config()
