"""Pure model-route configuration values."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RouteConfig:
    """Persistable, non-secret route definition."""

    name: str
    model: str
    base_url: str | None = None
    priority: int = 1
    max_concurrency: int = 2
    rpm: int | None = None
    tpm: int | None = None
    enabled: bool = True
    provider_id: str | None = None
    adapter_id: str | None = None
    transport: str | None = None
    model_id: str | None = None
    auth_scheme: str | None = None
    context_window_tokens: int | None = None
    max_output_tokens: int | None = None
    metadata_source: str | None = None
    metadata_confidence: str | None = None
    metadata_refreshed_at: str | None = None
    supports_tools: bool | None = None
    supports_vision: bool | None = None
    supports_reasoning: bool | None = None
    quality_tier: str = "unknown"
    input_cost_per_million: float | None = None
    output_cost_per_million: float | None = None
    connection_revision: int = 1
    api_key_ref: str | None = None
    headers_ref: str | None = None
    api_key_env: str | None = field(default=None, repr=False, compare=False)
    headers_env: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.name = self.name.strip()
        self.model = self.model.strip()
        if not self.name or len(self.name) > 80:
            raise ValueError("route name must be 1-80 characters")
        if not self.model:
            raise ValueError("route model cannot be empty")
        if self.priority < 1:
            raise ValueError("route priority must be at least 1")
        if self.max_concurrency < 1:
            raise ValueError("route max_concurrency must be at least 1")
        if self.rpm is not None and self.rpm < 1:
            raise ValueError("route rpm must be at least 1")
        if self.tpm is not None and self.tpm < 1:
            raise ValueError("route tpm must be at least 1")
        if self.context_window_tokens is not None and self.context_window_tokens < 1:
            raise ValueError("route context_window_tokens must be positive")
        if self.max_output_tokens is not None and self.max_output_tokens < 1:
            raise ValueError("route max_output_tokens must be positive")
        if self.input_cost_per_million is not None and self.input_cost_per_million < 0:
            raise ValueError("route input cost cannot be negative")
        if self.output_cost_per_million is not None and self.output_cost_per_million < 0:
            raise ValueError("route output cost cannot be negative")
        if self.connection_revision < 1:
            raise ValueError("route connection_revision must be positive")

    @classmethod
    def from_dict(cls, value: dict[str, Any], *, allow_env: bool = False) -> RouteConfig:
        forbidden = value.keys() & {"api_key", "key", "token", "headers"}
        if forbidden:
            raise ValueError(
                "route files cannot contain literal secrets; use an environment reference"
            )
        allowed = {
            "name",
            "model",
            "base_url",
            "priority",
            "max_concurrency",
            "rpm",
            "tpm",
            "enabled",
            "provider_id",
            "adapter_id",
            "transport",
            "model_id",
            "auth_scheme",
            "context_window_tokens",
            "max_output_tokens",
            "metadata_source",
            "metadata_confidence",
            "metadata_refreshed_at",
            "supports_tools",
            "supports_vision",
            "supports_reasoning",
            "quality_tier",
            "input_cost_per_million",
            "output_cost_per_million",
            "connection_revision",
            "api_key_ref",
            "headers_ref",
        }
        if allow_env:
            allowed.update({"api_key_env", "headers_env"})
        extra = value.keys() - allowed
        if extra:
            raise ValueError(f"unsupported route fields: {', '.join(sorted(extra))}")
        return cls(**{key: value[key] for key in allowed if key in value})

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("api_key_env", None)
        result.pop("headers_env", None)
        return {key: value for key, value in result.items() if value is not None}

    def public_dict(self) -> dict[str, Any]:
        result = self.to_dict()
        result["has_api_key"] = bool(self.api_key_ref or self.api_key_env)
        result["has_headers"] = bool(self.headers_ref or self.headers_env)
        return result
