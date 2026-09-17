"""Explicit built-in provider adapters.

Only providers with a declared authentication/configuration contract appear in
the TUI.  Unknown LiteLLM provider identifiers are intentionally not promoted
to a generic form.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

import requests

from strix.config.app_config import (
    ConnectionProfile,
    ModelDescriptor,
    get_config_service,
)
from strix.config.provider_catalog import adapter_models, model_metadata
from strix.domain.routes import RouteConfig
from strix.providers.base import CapabilityVerification, ProviderDefinition, ProviderField
from strix.providers.policy import quality_tier
from strix.security import get_secret_store, redact_secrets, register_secret


_model_cache: dict[str, tuple[float, list[ModelDescriptor]]] = {}


def _endpoint(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Endpoint must be an absolute HTTP or HTTPS URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Endpoint cannot contain credentials, a query string, or a fragment")
    path = parts.path.rstrip("/")
    for suffix in ("/chat/completions", "/responses", "/completions"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return urlunsplit((parts.scheme, parts.netloc, path, "", "")).rstrip("/")


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


@dataclass(slots=True)
class BuiltinProviderAdapter:
    spec: ProviderDefinition
    api_version: int = 2

    def definition(self) -> ProviderDefinition:
        return self.spec.model_copy(deep=True)

    def detect_connections(self) -> list[ConnectionProfile]:
        found: list[ConnectionProfile] = []
        for variable in self.spec.env:
            if os.environ.get(variable, "").strip():
                found.append(
                    ConnectionProfile(
                        id=f"env:{self.spec.id}:{variable.lower()}",
                        provider_id=self.spec.id,
                        name=f"{self.spec.name} ({variable})",
                        auth_source="environment",
                        options={"api_key_env": variable},
                    )
                )
                break
        if self.spec.auth_methods == ("none",):
            found.append(
                ConnectionProfile(
                    id=f"detected:{self.spec.id}",
                    provider_id=self.spec.id,
                    name=self.spec.name,
                    auth_source="none",
                    options={"base_url": self.spec.default_base_url},
                )
            )
        return found

    def connect(self, payload: dict[str, Any]) -> ConnectionProfile:
        service = get_config_service()
        requested_id = str(payload.get("connection_id") or "").strip()
        connection_id = requested_id or self.spec.id
        if not requested_id:
            existing = service.load().connections
            suffix = 2
            while connection_id in existing:
                connection_id = f"{self.spec.id}-{suffix}"
                suffix += 1
        name = str(payload.get("name") or self.spec.name).strip()
        auth_method = str(payload.get("auth_method") or self.spec.auth_methods[0])
        detected_env = next(
            (variable for variable in self.spec.env if os.environ.get(variable, "").strip()),
            None,
        )
        if auth_method == "environment" and detected_env is None:
            raise ValueError(
                f"No declared environment credential was detected for {self.spec.name}"
            )
        if auth_method != "environment" and auth_method not in self.spec.auth_methods:
            raise ValueError(f"Unsupported authentication method for {self.spec.name}")
        options: dict[str, str] = {}
        allowed = {field.id: field for field in self.spec.fields}
        for field_id, field in allowed.items():
            if field.kind == "secret":
                continue
            value = str(payload.get(field_id) or "").strip()
            if field.required and not value:
                raise ValueError(f"{field.label} is required")
            if value:
                options[field_id] = _endpoint(value) if field_id == "base_url" else value
        if self.spec.default_base_url and "base_url" not in options:
            options["base_url"] = self.spec.default_base_url
        if auth_method == "environment" and detected_env is not None:
            options["api_key_env"] = detected_env
        api_key = str(payload.get("api_key") or "").strip()
        if "\n" in api_key or "\r" in api_key:
            raise ValueError("API key must be a single line")
        if auth_method == "api_key" and not api_key:
            raise ValueError("API key is required")
        auth_source = {
            "api_key": "keychain",
            "oauth": "oauth",
            "credential_chain": "credential_chain",
            "none": "none",
            "environment": "environment",
        }[auth_method]
        profile = ConnectionProfile(
            id=connection_id,
            provider_id=self.spec.id,
            name=name,
            auth_source=cast("Any", auth_source),
            options=options,
        )
        return service.upsert_connection(
            profile, secret=api_key if auth_method == "api_key" else None
        )

    def disconnect(self, connection_id: str) -> bool:
        return get_config_service().disconnect(connection_id)

    def _credential(self, connection: ConnectionProfile) -> str:
        if connection.secret_ref:
            return get_secret_store().get(connection.secret_ref) or ""
        env = connection.options.get("api_key_env", "")
        return os.environ.get(env, "") if env else ""

    def discover_models(
        self, connection: ConnectionProfile, *, refresh: bool = False
    ) -> list[ModelDescriptor]:
        credential = self._credential(connection)
        endpoint = connection.options.get("base_url") or self.spec.default_base_url
        cache_key = hashlib.sha256(
            f"{connection.provider_id}:{connection.revision}:{endpoint}:{credential}".encode()
        ).hexdigest()
        cached = _model_cache.get(cache_key)
        if cached and not refresh and time.monotonic() - cached[0] < 3600:
            return [item.model_copy(deep=True) for item in cached[1]]

        entries: list[dict[str, Any]] = []
        if self.spec.model_discovery in {"openai", "local"} and endpoint:
            entries = self._discover_openai(endpoint, credential)
        elif self.spec.model_discovery == "gemini" and endpoint:
            entries = self._discover_gemini(endpoint, credential)
        if not entries:
            entries = adapter_models(self.spec.adapter_id)

        result = [self._descriptor(connection, entry) for entry in entries]
        _model_cache[cache_key] = (time.monotonic(), result)
        while len(_model_cache) > 100:
            _model_cache.pop(next(iter(_model_cache)))
        return [item.model_copy(deep=True) for item in result]

    def _discover_openai(self, endpoint: str, credential: str) -> list[dict[str, Any]]:
        register_secret(credential)
        headers = {"Authorization": f"Bearer {credential}"} if credential else {}
        try:
            response = requests.get(
                _endpoint(endpoint) + "/models",
                headers=headers,
                timeout=10,
                allow_redirects=False,
            )
            response.raise_for_status()
            if len(response.content) > 10 * 1024 * 1024:
                raise ValueError("Model catalog response exceeds 10 MiB")  # noqa: TRY301
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
                raise TypeError("Provider returned an invalid model list")  # noqa: TRY301
            return [
                cast("dict[str, Any]", item) for item in payload["data"] if isinstance(item, dict)
            ]
        except (requests.RequestException, ValueError, TypeError) as exc:
            raise RuntimeError(redact_secrets(str(exc))) from exc

    def _discover_gemini(self, endpoint: str, credential: str) -> list[dict[str, Any]]:
        register_secret(credential)
        headers = {"x-goog-api-key": credential} if credential else {}
        try:
            response = requests.get(
                _endpoint(endpoint) + "/models",
                headers=headers,
                timeout=10,
                allow_redirects=False,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
                raise TypeError("Gemini returned an invalid model list")  # noqa: TRY301
            return [
                cast("dict[str, Any]", item) for item in payload["models"] if isinstance(item, dict)
            ]
        except (requests.RequestException, ValueError, TypeError) as exc:
            raise RuntimeError(redact_secrets(str(exc))) from exc

    def _descriptor(self, connection: ConnectionProfile, entry: dict[str, Any]) -> ModelDescriptor:
        opaque = str(entry.get("id") or entry.get("name") or "").removeprefix("models/")
        if not opaque:
            raise ValueError("Provider returned a model without an ID")
        metadata = model_metadata(f"{self.spec.adapter_id}/{opaque}")
        supports_tools = entry.get("supports_tools", entry.get("tool_call"))
        if not isinstance(supports_tools, bool):
            supports_tools = metadata.get("supports_tools")
        return ModelDescriptor(
            id=f"{connection.id}:{opaque}",
            provider_id=self.spec.id,
            connection_id=connection.id,
            model_id=opaque,
            adapter_id=self.spec.adapter_id,
            supports_tools=supports_tools if isinstance(supports_tools, bool) else None,
            supports_vision=entry.get("supports_vision")
            if isinstance(entry.get("supports_vision"), bool)
            else metadata.get("supports_vision")
            if isinstance(metadata.get("supports_vision"), bool)
            else None,
            supports_reasoning=entry.get("supports_reasoning")
            if isinstance(entry.get("supports_reasoning"), bool)
            else metadata.get("supports_reasoning")
            if isinstance(metadata.get("supports_reasoning"), bool)
            else None,
            context_window_tokens=_positive_int(
                entry.get("context_window")
                or entry.get("context_length")
                or metadata.get("context_window_tokens")
            ),
            max_output_tokens=_positive_int(
                entry.get("max_output_tokens") or metadata.get("max_output_tokens")
            ),
            metadata_source=str(entry.get("source") or metadata.get("source") or "provider"),
            metadata_confidence=cast(
                "Any",
                metadata.get("confidence")
                if metadata.get("confidence") in {"verified", "catalog", "unknown"}
                else "discovered",
            ),
            quality_tier=cast("Any", quality_tier(self.spec.id, self.spec.adapter_id, opaque)),
            input_cost_per_million=metadata.get("input_cost_per_million")
            if isinstance(metadata.get("input_cost_per_million"), int | float)
            else None,
            output_cost_per_million=metadata.get("output_cost_per_million")
            if isinstance(metadata.get("output_cost_per_million"), int | float)
            else None,
        )

    def build_model(self, connection: ConnectionProfile, model: ModelDescriptor) -> RouteConfig:
        api_key_env = connection.options.get("api_key_env")
        return RouteConfig(
            name=model.id,
            model=f"{model.adapter_id}/{model.model_id}",
            base_url=connection.options.get("base_url") or None,
            provider_id=connection.provider_id,
            adapter_id=model.adapter_id,
            transport=self.spec.transport,
            model_id=model.model_id,
            auth_scheme=self.spec.auth_methods[0],
            context_window_tokens=model.context_window_tokens,
            max_output_tokens=model.max_output_tokens,
            metadata_source=model.metadata_source,
            metadata_confidence=model.metadata_confidence,
            api_key_ref=connection.secret_ref,
            api_key_env=api_key_env,
        )

    def verify_capabilities(
        self, connection: ConnectionProfile, model: ModelDescriptor
    ) -> CapabilityVerification:
        del connection
        return CapabilityVerification(
            supports_tools=model.supports_tools,
            supports_vision=model.supports_vision,
            context_window_tokens=model.context_window_tokens,
            max_output_tokens=model.max_output_tokens,
            source=model.metadata_source,
        )


def _field(
    identifier: str,
    label: str,
    *,
    required: bool = False,
    secret: bool = False,
    advanced: bool = False,
) -> ProviderField:
    return ProviderField(
        id=identifier,
        label=label,
        kind="secret" if secret else "text",
        required=required,
        advanced=advanced,
    )


def builtin_adapters() -> tuple[BuiltinProviderAdapter, ...]:
    api_key = (_field("api_key", "API key", required=True, secret=True),)
    specs = (
        ProviderDefinition(
            id="openai",
            name="OpenAI",
            adapter_id="openai",
            transport="openai",
            auth_methods=("api_key",),
            fields=api_key,
            env=("OPENAI_API_KEY",),
            default_base_url="https://api.openai.com/v1",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="anthropic",
            name="Anthropic",
            adapter_id="anthropic",
            transport="anthropic",
            auth_methods=("api_key",),
            fields=api_key,
            env=("ANTHROPIC_API_KEY",),
            default_base_url="https://api.anthropic.com/v1",
            model_discovery="catalog",
        ),
        ProviderDefinition(
            id="gemini",
            name="Google Gemini",
            adapter_id="gemini",
            transport="gemini",
            auth_methods=("api_key",),
            fields=api_key,
            env=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
            default_base_url="https://generativelanguage.googleapis.com/v1beta",
            model_discovery="gemini",
        ),
        ProviderDefinition(
            id="openrouter",
            name="OpenRouter",
            adapter_id="openrouter",
            transport="litellm",
            auth_methods=("api_key",),
            fields=api_key,
            env=("OPENROUTER_API_KEY",),
            default_base_url="https://openrouter.ai/api/v1",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="tokenrouter",
            name="TokenRouter",
            adapter_id="openai",
            transport="openai",
            auth_methods=("api_key",),
            fields=api_key,
            env=("TOKENROUTER_API_KEY",),
            default_base_url="https://api.tokenrouter.com/v1",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="groq",
            name="Groq",
            adapter_id="groq",
            transport="litellm",
            auth_methods=("api_key",),
            fields=api_key,
            env=("GROQ_API_KEY",),
            default_base_url="https://api.groq.com/openai/v1",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="mistral",
            name="Mistral AI",
            adapter_id="mistral",
            transport="litellm",
            auth_methods=("api_key",),
            fields=api_key,
            env=("MISTRAL_API_KEY",),
            default_base_url="https://api.mistral.ai/v1",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="deepseek",
            name="DeepSeek",
            adapter_id="deepseek",
            transport="litellm",
            auth_methods=("api_key",),
            fields=api_key,
            env=("DEEPSEEK_API_KEY",),
            default_base_url="https://api.deepseek.com",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="together_ai",
            name="Together AI",
            adapter_id="together_ai",
            transport="litellm",
            auth_methods=("api_key",),
            fields=api_key,
            env=("TOGETHERAI_API_KEY",),
            default_base_url="https://api.together.xyz/v1",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="fireworks_ai",
            name="Fireworks AI",
            adapter_id="fireworks_ai",
            transport="litellm",
            auth_methods=("api_key",),
            fields=api_key,
            env=("FIREWORKS_AI_API_KEY",),
            default_base_url="https://api.fireworks.ai/inference/v1",
            model_discovery="openai",
        ),
        ProviderDefinition(
            id="ollama",
            name="Ollama",
            adapter_id="ollama_chat",
            transport="litellm",
            auth_methods=("none",),
            default_base_url="http://localhost:11434/v1",
            model_discovery="local",
        ),
        ProviderDefinition(
            id="custom",
            name="Custom OpenAI-compatible",
            adapter_id="openai",
            transport="openai",
            auth_methods=("api_key", "none"),
            fields=(
                _field("api_key", "API key", secret=True),
                _field("base_url", "Base URL", required=True),
            ),
            model_discovery="openai",
        ),
    )
    return tuple(BuiltinProviderAdapter(spec) for spec in specs)


__all__ = ["BuiltinProviderAdapter", "builtin_adapters"]
