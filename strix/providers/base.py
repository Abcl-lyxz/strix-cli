"""Public provider plugin contract for Strix v2."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


if TYPE_CHECKING:
    from strix.config.app_config import ConnectionProfile, ModelDescriptor
    from strix.domain.routes import RouteConfig


class ProviderField(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    kind: Literal["text", "secret", "choice", "boolean"] = "text"
    required: bool = False
    advanced: bool = False
    choices: tuple[str, ...] = ()
    placeholder: str = ""


class ProviderDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    adapter_id: str
    transport: Literal["openai", "anthropic", "gemini", "litellm", "subscription"]
    auth_methods: tuple[str, ...]
    fields: tuple[ProviderField, ...] = ()
    env: tuple[str, ...] = ()
    default_base_url: str = ""
    model_discovery: Literal["openai", "gemini", "catalog", "local", "none"] = "catalog"
    plugin: str = "builtin"


class CapabilityVerification(BaseModel):
    supports_tools: bool | None = None
    supports_vision: bool | None = None
    context_window_tokens: int | None = Field(default=None, ge=1)
    max_output_tokens: int | None = Field(default=None, ge=1)
    source: str = "adapter"


@runtime_checkable
class ProviderAdapter(Protocol):
    """Versioned entry-point interface implemented by provider plugins."""

    api_version: int

    def definition(self) -> ProviderDefinition: ...

    def detect_connections(self) -> list[ConnectionProfile]: ...

    def connect(self, payload: dict[str, Any]) -> ConnectionProfile: ...

    def disconnect(self, connection_id: str) -> bool: ...

    def discover_models(
        self, connection: ConnectionProfile, *, refresh: bool = False
    ) -> list[ModelDescriptor]: ...

    def build_model(self, connection: ConnectionProfile, model: ModelDescriptor) -> RouteConfig: ...

    def verify_capabilities(
        self, connection: ConnectionProfile, model: ModelDescriptor
    ) -> CapabilityVerification: ...


__all__ = [
    "CapabilityVerification",
    "ProviderAdapter",
    "ProviderDefinition",
    "ProviderField",
]
