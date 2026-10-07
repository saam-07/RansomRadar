"""
Configuration loader and validator for the AdaptShield endpoint agent.
Supports YAML file loading, environment overrides, and strict Pydantic validation.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


class WatchConfig(BaseModel):
    paths: list[str] = Field(
        default_factory=lambda: ["/home", "/srv", "/var/www", "/opt/data"],
        description="Directories monitored by fanotify",
    )
    excludes: list[str] = Field(
        default_factory=lambda: [
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/tmp",
            "/var/lib/adaptshield",
            "/var/log/adaptshield",
            "/var/cache/apt",
        ],
        description="Paths excluded from fanotify events to prevent feedback loops",
    )


class ResponseConfig(BaseModel):
    policy: str = Field(
        default="immediate",
        description="Containment policy: 'immediate', 'manual', or 'none'",
    )
    auto_resolve_after_seconds: float = Field(
        default=300.0,
        ge=0.0,
        description="Timeout for manual decisions before auto-resolving",
    )
    auto_resolve_action: str = Field(
        default="release",
        description="Action on manual timeout: 'release' or 'confirm'",
    )
    use_freeze: bool = Field(
        default=True,
        description="Whether to use cgroup freezer on containment",
    )
    quarantine_dir: str = Field(
        default="/var/lib/adaptshield/quarantine",
        description="Directory for quarantined file copies prior to rollback",
    )
    control_dir: str = Field(
        default="/var/lib/adaptshield/control",
        description="Directory for manual containment decisions",
    )

    @field_validator("policy")
    @classmethod
    def validate_policy(cls, v: str) -> str:
        v = v.lower()
        if v not in {"none", "immediate", "manual"}:
            raise ValueError(f"Invalid policy '{v}'. Must be one of: none, immediate, manual")
        return v

    @field_validator("auto_resolve_action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        v = v.lower()
        if v not in {"release", "confirm"}:
            raise ValueError(f"Invalid auto_resolve_action '{v}'. Must be 'release' or 'confirm'")
        return v


class ThresholdsConfig(BaseModel):
    elevated: float = Field(default=0.3, ge=0.0, le=1.0)
    suspicious: float = Field(default=0.6, ge=0.0, le=1.0)
    critical: float = Field(default=0.85, ge=0.0, le=1.0)


class DetectionConfig(BaseModel):
    window_seconds: float = Field(default=2.0, gt=0.0)
    theta0: float = Field(default=0.5, ge=0.0, le=1.0)
    use_escalation: bool = Field(default=True)
    use_tier1: bool = Field(default=True)
    use_risk_smoothing: bool = Field(default=True)
    ewma_alpha: float = Field(default=0.3, gt=0.0, le=1.0)
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    consecutive_windows_for_critical: int = Field(default=2, ge=1)


class AllowlistConfig(BaseModel):
    process_names: list[str] = Field(
        default_factory=lambda: [
            "systemd",
            "systemd-journald",
            "systemd-udevd",
            "sshd",
            "dbus-daemon",
            "dockerd",
            "containerd",
            "rsync",
            "tar",
            "restic",
            "borg",
            "mysqld",
            "postgres",
            "code",
            "python",
            "adaptshield",
            "adaptshield-agent",
        ]
    )
    exe_paths: list[str] = Field(
        default_factory=lambda: [
            "/usr/lib/systemd/*",
            "/usr/sbin/sshd",
        ]
    )
    users: list[str] = Field(default_factory=lambda: ["root"])


class SafetyRailsConfig(BaseModel):
    max_containments_per_minute: int = Field(default=10, ge=1)
    storm_threshold_distinct_pids: int = Field(default=5, ge=1)
    storm_window_seconds: int = Field(default=30, ge=1)


class ClassifierConfig(BaseModel):
    mode: str = Field(default="auto")
    allow_synthetic: bool = Field(default=False)
    model_name: str = Field(default="xgboost")
    registry_dir: str = Field(default="models/registry")
    model_path: str | None = Field(default=None)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        v = v.lower()
        if v not in {"auto", "rule_based", "xgboost", "random_forest"}:
            raise ValueError(
                f"Invalid classifier mode '{v}'. Must be one of: auto, rule_based, xgboost, random_forest"
            )
        return v


class TelemetryConfig(BaseModel):
    enabled: bool = Field(default=False)
    dir: str = Field(default="/var/lib/adaptshield/telemetry")
    rotation_mb: int = Field(default=50, ge=1)


class LoggingConfig(BaseModel):
    level: str = Field(default="INFO")
    file: str = Field(default="/var/log/adaptshield/adaptshield.log")
    alert_file: str = Field(default="/var/log/adaptshield/alert.jsonl")
    max_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    backup_count: int = Field(default=5, ge=0)
    use_journald: bool = Field(default=False)


class AdaptShieldConfig(BaseModel):
    mode: str = Field(default="protect")
    monitor_first_period_hours: int = Field(default=24, ge=0)
    watch: WatchConfig = Field(default_factory=WatchConfig)
    protect_paths: list[str] = Field(default_factory=lambda: ["/home"])
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)
    safety_rails: SafetyRailsConfig = Field(default_factory=SafetyRailsConfig)
    classifier: ClassifierConfig = Field(default_factory=ClassifierConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("mode")
    @classmethod
    def validate_operating_mode(cls, v: str) -> str:
        v = v.lower()
        if v not in {"monitor", "protect", "learn"}:
            raise ValueError(f"Invalid mode '{v}'. Must be one of: monitor, protect, learn")
        return v


def load_config(path: str | Path | None = None) -> AdaptShieldConfig:
    """Loads configuration from specified file path, default locations, or defaults."""
    candidates = []
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        candidates.append(p)
    else:
        # Check standard locations in priority order
        env_path = os.getenv("ADAPTSHIELD_CONFIG")
        if env_path:
            candidates.append(Path(env_path))
        candidates.extend([
            Path("/etc/adaptshield/config.yaml"),
            Path("packaging/config.default.yaml"),
            Path("config.yaml"),
        ])

    for c in candidates:
        try:
            if c.exists() and c.is_file():
                try:
                    with open(c, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                    return AdaptShieldConfig(**data)
                except Exception as e:
                    if path is not None:
                        raise ValueError(f"Error parsing configuration file {c}: {e}") from e
                    # Otherwise, continue search
        except PermissionError:
            if path is not None:
                raise
            continue
        except OSError:
            if path is not None:
                raise
            continue

    # If no configuration file was found or readable, return default configuration
    return AdaptShieldConfig()
