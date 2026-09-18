from __future__ import annotations

from typing import Any

import pytest

from strix.config.app_config import ConnectionProfile, get_config_service
from strix.providers.base import CapabilityVerification, ProviderDefinition, ProviderField
from strix.providers.registry import ProviderRegistry


class _FakeAdapter:
    api_version = 2

    def definition(self) -> ProviderDefinition:
        return ProviderDefinition(
            id="fixture",
            name="Fixture Cloud",
            adapter_id="fixture",
            transport="litellm",
            auth_methods=("api_key",),
            fields=(
                ProviderField(id="api_key", label="API key", kind="secret", required=True),
                ProviderField(id="tenant", label="Tenant", required=True),
            ),
            model_discovery="none",
            plugin="fixture-plugin",
        )

    def detect_connections(self) -> list[ConnectionProfile]:
        return []

    def connect(self, payload: dict[str, Any]) -> ConnectionProfile:
        if not str(payload.get("tenant") or "").strip():
            raise ValueError("Tenant is required")
        if payload.get("model_id"):
            raise ValueError("connect must not select a model")
        profile = ConnectionProfile(
            id="fixture",
            provider_id="fixture",
            name="Fixture Cloud",
            auth_source="keychain",
            options={"tenant": str(payload["tenant"])},
        )
        return get_config_service().upsert_connection(
            profile, secret=str(payload.get("api_key") or "")
        )

    def disconnect(self, connection_id: str) -> bool:
        return get_config_service().disconnect(connection_id)

    def discover_models(self, *_args: Any, **_kwargs: Any) -> list[Any]:
        return []

    def build_model(self, *_args: Any, **_kwargs: Any) -> Any:
        raise NotImplementedError

    def verify_capabilities(self, *_args: Any, **_kwargs: Any) -> CapabilityVerification:
        return CapabilityVerification(source="fixture")


def test_fake_provider_connects_with_provider_fields_and_without_a_model() -> None:
    registry = ProviderRegistry(load_plugins=False)
    registry.register(_FakeAdapter())
    adapter = registry.adapter("fixture")

    connection = adapter.connect({"tenant": "acme", "api_key": "fixture-secret"})

    assert connection.options == {"tenant": "acme"}
    assert get_config_service().load().models == {}


def test_builtin_registry_exposes_base_url_only_for_custom_or_local_runtime() -> None:
    definitions = {item.id: item for item in ProviderRegistry(load_plugins=False).definitions()}
    assert "bedrock" not in definitions
    assert all(field.id != "base_url" for field in definitions["openai"].fields)
    assert any(field.id == "base_url" for field in definitions["custom"].fields)


def test_detected_environment_credential_requires_explicit_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "environment-secret")
    registry = ProviderRegistry(load_plugins=False)
    detected = [item for item in registry.detected_connections() if item.provider_id == "openai"]

    assert detected and detected[0].auth_source == "environment"
    assert get_config_service().load().connections == {}

    connection = registry.adapter("openai").connect(
        {"auth_method": "environment", "name": "OpenAI environment"}
    )

    assert connection.auth_source == "environment"
    assert connection.secret_ref is None
    assert connection.options["api_key_env"] == "OPENAI_API_KEY"


def test_registry_rejects_incompatible_plugin_api() -> None:
    adapter = _FakeAdapter()
    adapter.api_version = 1
    with pytest.raises(ValueError, match="api_version must be 2"):
        ProviderRegistry(load_plugins=False).register(adapter)  # type: ignore[arg-type]


def test_live_provider_with_empty_catalog_does_not_inherit_adapter_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = ProviderRegistry(load_plugins=False).adapter("custom")
    connection = adapter.connect(
        {
            "base_url": "https://gateway.invalid/v1",
            "api_key": "fixture-key",
        }
    )
    monkeypatch.setattr(type(adapter), "_discover_openai", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        "strix.providers.builtin.adapter_models",
        lambda _adapter_id: pytest.fail("live discovery must not use adapter-wide models"),
    )

    assert adapter.discover_models(connection, refresh=True) == []
