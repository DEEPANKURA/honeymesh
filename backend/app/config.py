from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

RISK_WEIGHT_KEYS = ("recon", "credential", "web", "discovery", "lateral", "persistence")


class EnvironmentConfig(BaseModel):
    mode: str = "lab"


class ServiceConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./data/honeymesh.db"


class IngestConfig(BaseModel):
    token: str = ""
    rate_limit_per_minute: int = 6000


class AuthConfig(BaseModel):
    admin_username: str = "admin"
    admin_password: str = ""
    token_ttl_seconds: int = 43200
    require_read_auth: bool = False


class DetectionConfig(BaseModel):
    window_seconds: int = 300
    scan_threshold: int = 20
    brute_force_threshold: int = 10
    web_probe_threshold: int = 15
    discovery_threshold: int = 8
    lateral_threshold: int = 5
    persistence_threshold: int = 3
    min_events_for_classification: int = 5


class RiskConfig(BaseModel):
    weights: dict[str, float] = Field(default_factory=lambda: {k: 0.16 for k in RISK_WEIGHT_KEYS})
    velocity_weight: float = 0.15
    bands: dict[str, float] = Field(
        default_factory=lambda: {"low": 0.25, "moderate": 0.50, "high": 0.75}
    )

    @field_validator("weights")
    @classmethod
    def _known_weights(cls, value: dict[str, float]) -> dict[str, float]:
        unknown = set(value) - set(RISK_WEIGHT_KEYS)
        if unknown:
            raise ValueError(f"unknown risk weight keys: {sorted(unknown)}")
        return value


class DeceptionConfig(BaseModel):
    max_level: int = 5
    adaptive_mode: bool = True
    decision_interval_seconds: float = 2.0
    cooldown_seconds: float = 10.0

    @field_validator("max_level")
    @classmethod
    def _bounded_level(cls, value: int) -> int:
        if not 0 <= value <= 5:
            raise ValueError("max_level must be between 0 and 5")
        return value


class TelemetryConfig(BaseModel):
    level: str = "normal"


class LoggingConfig(BaseModel):
    level: str = "INFO"


class SSHSensorConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 2222
    banner: str = "SSH-2.0-OpenSSH_8.9p1"


class WebSensorConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8081


class NetworkSensorConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 9000


class SensorsConfig(BaseModel):
    ssh: SSHSensorConfig = Field(default_factory=SSHSensorConfig)
    web: WebSensorConfig = Field(default_factory=WebSensorConfig)
    network: NetworkSensorConfig = Field(default_factory=NetworkSensorConfig)


class DecoyConfig(BaseModel):
    type: str = "http"
    port: int
    host: str = "127.0.0.1"
    deception_level: int = 3
    auto_activate: bool = False


class PolicyConfig(BaseModel):
    name: str
    description: str = ""
    conditions: dict[str, str] = Field(default_factory=dict)
    actions: list[str] = Field(default_factory=list)
    escalate_to_level: int = 2


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HONEYMESH_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    environment: EnvironmentConfig = Field(default_factory=EnvironmentConfig)
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    ingest: IngestConfig = Field(default_factory=IngestConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    deception: DeceptionConfig = Field(default_factory=DeceptionConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    sensors: SensorsConfig = Field(default_factory=SensorsConfig)
    decoys: dict[str, DecoyConfig] = Field(default_factory=dict)
    policies: list[PolicyConfig] = Field(default_factory=list)


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(value, dict) and isinstance(existing, dict):
            merged[key] = _deep_merge(existing, value)
        else:
            merged[key] = value
    return merged


def config_files() -> list[Path]:
    root = Path(os.environ.get("HONEYMESH_CONFIG_DIR", "configs"))
    files = [root / "default.yaml"]
    extra = os.environ.get("HONEYMESH_CONFIG")
    if extra:
        files.append(Path(extra))
    return files


class YamlConfigSettingsSource(PydanticBaseSettingsSource):
    """YAML file source with precedence below environment variables."""

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return None, "", False

    def __call__(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for path in config_files():
            if not path.is_file():
                continue
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"config file {path} must contain a mapping")
            data = _deep_merge(data, loaded)
        return data


class HoneyMeshSettings(Settings):
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )


def load_settings(**overrides: Any) -> HoneyMeshSettings:
    return HoneyMeshSettings(**overrides)
