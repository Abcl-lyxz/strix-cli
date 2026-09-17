"""Versioned Strix v2 application configuration.

This module is the single persistence boundary for interactive configuration.
Legacy ``cli-config.json`` and route files are intentionally neither read nor
modified here.  Environment variables are discovery inputs owned by provider
adapters; they are not configuration overrides.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from strix.security import get_secret_store
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Callable


CONFIG_VERSION: Literal[3] = 3
ApplyScope = Literal["immediate", "next_request", "next_scan", "restart"]
AuthSource = Literal["keychain", "environment", "oauth", "credential_chain", "none"]
QualityTier = Literal["frontier", "strong", "standard", "economy", "unknown"]


class ConnectionProfile(BaseModel):
    """A non-secret provider connection saved by ``/connect``."""

    model_config = ConfigDict(extra="forbid")

    id: str
    provider_id: str
    name: str
    auth_source: AuthSource = "keychain"
    secret_ref: str | None = None
    options: dict[str, str] = Field(default_factory=dict)
    revision: int = 1
    enabled: bool = True

    @field_validator("id", "provider_id", "name")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value


class ModelDescriptor(BaseModel):
    """A provider model eligible for automatic routing."""

    model_config = ConfigDict(extra="forbid")

    id: str
    provider_id: str
    connection_id: str
    model_id: str
    adapter_id: str
    enabled: bool = False
    supports_tools: bool | None = None
    supports_vision: bool | None = None
    supports_reasoning: bool | None = None
    context_window_tokens: int | None = Field(default=None, ge=1)
    max_output_tokens: int | None = Field(default=None, ge=1)
    input_cost_per_million: float | None = Field(default=None, ge=0)
    output_cost_per_million: float | None = Field(default=None, ge=0)
    quality_tier: QualityTier = "unknown"
    metadata_source: str = "unknown"
    metadata_confidence: Literal["verified", "catalog", "discovered", "unknown"] = "unknown"
    verified_at: str | None = None


class RouterPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strategy: Literal["quality_reliability"] = "quality_reliability"
    max_attempts_per_turn: int = Field(default=3, ge=1, le=3)
    max_consecutive_failed_turns: int = Field(default=3, ge=1, le=10)
    max_retry_input_multiplier: float = Field(default=2.0, ge=1.0, le=5.0)
    allow_unknown_capabilities: bool = False


class ScanDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_mode: Literal["quick", "standard", "deep"] = "deep"
    scope_mode: Literal["auto", "diff", "full"] = "auto"
    max_budget_usd: float | None = Field(default=None, gt=0)
    max_turns: int = Field(default=500, ge=1)
    max_agents: int = Field(default=12, ge=2)
    sandbox_profile: Literal["web", "network", "lan", "remediation"] = "web"
    tool_pack: str = "auto"
    workspace_mode: Literal["read-only", "read-write"] = "read-only"


class UiPreferences(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reasoning_effort: Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"] = "high"
    streaming_enabled: bool = True
    prompt_cache: bool = True
    llm_timeout_seconds: int = Field(default=300, ge=1, le=3_600)
    stream_idle_timeout_seconds: int = Field(default=300, ge=0, le=3_600)
    max_tool_calls_per_turn: int = Field(default=32, ge=0, le=256)
    max_context_images: int = Field(default=3, ge=0, le=32)
    external_editor: str = ""


class AppConfig(BaseModel):
    """Complete v3 configuration document."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[3] = CONFIG_VERSION
    revision: int = Field(default=0, ge=0)
    connections: dict[str, ConnectionProfile] = Field(default_factory=dict)
    models: dict[str, ModelDescriptor] = Field(default_factory=dict)
    router: RouterPolicy = Field(default_factory=RouterPolicy)
    scan_defaults: ScanDefaults = Field(default_factory=ScanDefaults)
    mcp: dict[str, dict[str, Any]] = Field(default_factory=dict)
    notifications: dict[str, dict[str, Any]] = Field(default_factory=dict)
    ui: UiPreferences = Field(default_factory=UiPreferences)


class AppConfigError(RuntimeError):
    """The v3 configuration exists but cannot be read safely."""


class ConfigService:
    """Atomic owner of v3 configuration and provider credentials."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path.home() / ".strix" / "config.json"
        self._lock = threading.RLock()
        self._last_good: AppConfig | None = None

    def load(self) -> AppConfig:
        with self._lock:
            if not self.path.exists():
                config = AppConfig()
                self._last_good = config
                return config.model_copy(deep=True)
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                config = AppConfig.model_validate(raw)
            except (OSError, json.JSONDecodeError, ValidationError, TypeError) as exc:
                if self._last_good is not None:
                    raise AppConfigError(
                        f"Cannot read {self.path}; the last known good configuration "
                        f"remains active: {exc}"
                    ) from exc
                raise AppConfigError(
                    f"Cannot read {self.path}. Fix or move the invalid file; "
                    f"Strix will not overwrite it: {exc}"
                ) from exc
            self._last_good = config
            return config.model_copy(deep=True)

    def save(self, config: AppConfig) -> AppConfig:
        with self._lock:
            current_revision = self._last_good.revision if self._last_good is not None else -1
            saved = config.model_copy(
                update={"version": CONFIG_VERSION, "revision": current_revision + 1}
            )
            write_secret_text(
                self.path,
                json.dumps(saved.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
            )
            self._last_good = saved
            return saved.model_copy(deep=True)

    def update(self, transform: Callable[[AppConfig], AppConfig | None]) -> AppConfig:
        with self._lock:
            current = self.load()
            replacement = transform(current) or current
            return self.save(replacement)

    def upsert_connection(
        self,
        profile: ConnectionProfile,
        *,
        secret: str | None = None,
    ) -> ConnectionProfile:
        """Persist a connection and rotate its secret without leaking old refs."""

        store = get_secret_store()
        current = self.load()
        previous = current.connections.get(profile.id)
        new_ref = profile.secret_ref
        if secret is not None:
            new_ref = f"v3.connection.{profile.id}.r{(previous.revision + 1) if previous else 1}"
            store.set(new_ref, secret.strip())
        revision = (previous.revision + 1) if previous else max(1, profile.revision)
        updated = profile.model_copy(update={"secret_ref": new_ref, "revision": revision})
        current.connections[updated.id] = updated
        try:
            self.save(current)
        except Exception:
            if secret is not None and new_ref is not None:
                store.delete(new_ref)
            raise
        if previous and previous.secret_ref and previous.secret_ref != new_ref:
            store.delete(previous.secret_ref)
        return updated

    def disconnect(self, connection_id: str) -> bool:
        current = self.load()
        profile = current.connections.pop(connection_id, None)
        if profile is None:
            return False
        current.models = {
            key: value
            for key, value in current.models.items()
            if value.connection_id != connection_id
        }
        self.save(current)
        if profile.secret_ref:
            get_secret_store().delete(profile.secret_ref)
        return True

    def upsert_models(self, models: list[ModelDescriptor]) -> AppConfig:
        current = self.load()
        for model in models:
            if model.connection_id not in current.connections:
                raise ValueError(f"Unknown connection: {model.connection_id}")
            current.models[model.id] = model
        return self.save(current)

    def set_model_enabled(self, model_id: str, enabled: bool) -> ModelDescriptor:
        current = self.load()
        if model_id not in current.models:
            raise ValueError(f"Unknown model: {model_id}")
        updated = current.models[model_id].model_copy(update={"enabled": enabled})
        current.models[model_id] = updated
        self.save(current)
        return updated


_service: ConfigService | None = None


def get_config_service() -> ConfigService:
    global _service  # noqa: PLW0603
    if _service is None:
        _service = ConfigService()
    return _service


def set_config_service(service: ConfigService | None) -> None:
    """Replace the process service; intended for tests and embedded clients."""

    global _service  # noqa: PLW0603
    _service = service


__all__ = [
    "CONFIG_VERSION",
    "AppConfig",
    "AppConfigError",
    "ApplyScope",
    "ConfigService",
    "ConnectionProfile",
    "ModelDescriptor",
    "RouterPolicy",
    "ScanDefaults",
    "UiPreferences",
    "get_config_service",
    "set_config_service",
]
