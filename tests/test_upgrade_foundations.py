"""Provider-catalog and explicit sandbox-profile regression coverage."""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from strix.config.loader import set_session_field
from strix.config.provider_catalog import model_metadata, refresh_provider_catalog
from strix.config.providers import connect_provider
from strix.config.routes import session_routes
from strix.runtime import profiles
from strix.tools.proxy.tools import _repair_httpql, _validate_httpql
from strix.tools.security_jobs.tool import _validate_network_arguments


class _CatalogResponse:
    status_code = 200
    headers: ClassVar[dict[str, str]] = {"ETag": '"catalog-v2"'}
    content = b"{}"

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {
            "provider-x": {
                "name": "Provider X",
                "api": "https://models.example/v1",
                "models": {"opaque/id": {"limit": {"context": 65_536}}},
            }
        }


def test_unknown_model_uses_conservative_context_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("strix.config.provider_catalog._litellm_model_info", lambda _name: None)

    metadata = model_metadata("custom/never-before-seen")

    assert metadata["context_window_tokens"] == 32_768
    assert metadata["confidence"] == "unknown"


def test_catalog_refresh_is_atomic_and_keeps_release_recommendations(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "providers.json"
    monkeypatch.setenv("STRIX_PROVIDER_CATALOG", str(destination))
    monkeypatch.setattr(
        "strix.config.provider_catalog.requests.get", lambda *_a, **_k: _CatalogResponse()
    )

    result = refresh_provider_catalog(force=True)
    stored = json.loads(destination.read_text(encoding="utf-8"))

    assert result["source"] == "network"
    assert stored["etag"] == '"catalog-v2"'
    assert stored["providers"][0]["id"] == "provider-x"
    assert stored["recommended_models"]


def test_endpointless_runtime_adapter_can_be_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("strix.config.providers.adapter_models", lambda _provider: [])
    monkeypatch.setattr(
        "strix.config.providers.model_metadata",
        lambda _model: {
            "context_window_tokens": 32_768,
            "max_output_tokens": 8_192,
            "source": "conservative-default",
            "confidence": "unknown",
        },
    )

    connect_provider(
        {
            "provider_id": "bedrock",
            "model_id": "vendor.opaque-model:v1",
            "name": "aws-runtime",
            "persist": False,
        }
    )
    route = session_routes()["aws-runtime"]

    assert route.base_url is None
    assert route.provider_id == "bedrock"
    assert route.model_id == "vendor.opaque-model:v1"
    assert route.model == "bedrock/vendor.opaque-model:v1"


def test_web_profile_is_read_only_and_drops_capabilities() -> None:
    preflight = profiles.preflight_profile()
    create_kwargs: dict[str, Any] = {}
    profiles.apply_profile(create_kwargs)

    assert preflight["profile"] == "web"
    assert preflight["workspace_mode"] == "read-only"
    assert create_kwargs["cap_drop"] == ["ALL"]
    assert create_kwargs["cap_add"] == []
    assert create_kwargs["read_only"] is True


def test_network_profile_requires_explicit_cidr() -> None:
    set_session_field("runtime", "sandbox_profile", "network")

    with pytest.raises(ValueError, match="requires --scope-cidr"):
        profiles.preflight_profile()


def test_lan_profile_refuses_windows_even_with_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_session_field("runtime", "sandbox_profile", "lan")
    set_session_field("runtime", "scope_cidr", "192.0.2.0/24")
    set_session_field("runtime", "network_interface", "Ethernet")
    set_session_field("runtime", "packet_rate_limit", 100)
    acknowledged = True
    set_session_field("runtime", "lan_acknowledged", acknowledged)
    monkeypatch.setattr(profiles.sys, "platform", "win32")

    with pytest.raises(ValueError, match="native Linux"):
        profiles.preflight_profile()


def test_writable_workspace_requires_remediation_profile() -> None:
    set_session_field("runtime", "workspace_mode", "read-write")

    with pytest.raises(ValueError, match="requires --sandbox-profile remediation"):
        profiles.preflight_profile()


def test_remediation_source_stays_read_only_until_write_mode_is_explicit() -> None:
    set_session_field("runtime", "sandbox_profile", "remediation")

    assert profiles.preflight_profile()["workspace_mode"] == "read-only"


def test_network_job_scope_validation_ignores_ports_but_rejects_escape() -> None:
    _validate_network_arguments(["-p", "80", "192.0.2.10"], "192.0.2.0/24")

    with pytest.raises(ValueError, match="outside --scope-cidr"):
        _validate_network_arguments(["198.51.100.4"], "192.0.2.0/24")


def test_httpql_validation_and_single_grammar_aware_repair() -> None:
    invalid = 'req.method=="GET" && resp.code.eq:"200"'
    repaired = _repair_httpql(invalid)

    assert repaired == 'req.method.eq:"GET" AND resp.code.eq:200'
    assert _validate_httpql(repaired) is None
    assert "no NOT operator" in (_validate_httpql('NOT req.path.eq:"/admin"') or "")
