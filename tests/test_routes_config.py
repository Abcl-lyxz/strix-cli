"""Route configuration, process-only overrides, and credential references."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from strix.config import loader
from strix.config.routes import (
    list_saved_routes,
    load_routes,
    remove_route,
    save_route,
    set_route_enabled,
    set_route_key,
)
from strix.routing import RouteConfig, RoutePool, _resolve_route_secrets
from strix.security import get_secret_store


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated_routes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "cli-config.json"
    monkeypatch.setattr(loader, "_override", path)
    monkeypatch.setattr(loader, "_cached", None)
    for name in (
        "STRIX_ROUTES_FILE",
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "OPENAI_API_BASE",
    ):
        monkeypatch.delenv(name, raising=False)
    return path


def _settings(model: str = "openai/default") -> SimpleNamespace:
    return SimpleNamespace(llm=SimpleNamespace(model=model, api_base=None))


def test_saved_route_crud_contains_references_but_no_plaintext(
    _isolated_routes: Path,
) -> None:
    save_route(RouteConfig(name="primary", model="openai/one", max_concurrency=4))
    ref = set_route_key("primary", "sk-private-value")
    assert set_route_enabled("primary", enabled=False) is True

    raw = _isolated_routes.read_text(encoding="utf-8")
    route = list_saved_routes()[0]
    assert "sk-private-value" not in raw
    assert route.api_key_ref == ref
    assert route.enabled is False
    assert get_secret_store().get(ref) == "sk-private-value"

    assert remove_route("primary") is True
    assert list_saved_routes() == []
    assert get_secret_store().get(ref) is None


def test_legacy_environment_route_overrides_saved_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    save_route(RouteConfig(name="saved", model="openai/saved"))
    monkeypatch.setenv("STRIX_LLM", "openrouter/process")
    monkeypatch.setenv("LLM_API_KEY", "process-key")

    routes = load_routes(_settings("openrouter/process"))

    assert len(routes) == 1
    assert routes[0].name == "environment"
    assert routes[0].api_key_env == "LLM_API_KEY"
    assert _resolve_route_secrets(routes[0])[0] == "process-key"


def test_headless_route_file_accepts_env_references_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route_file = tmp_path / "routes.json"
    route_file.write_text(
        json.dumps(
            {
                "routes": [
                    {
                        "name": "ci",
                        "model": "openai/ci",
                        "api_key_env": "CI_LLM_KEY",
                        "headers_env": "CI_LLM_HEADERS",
                        "priority": 2,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("STRIX_ROUTES_FILE", str(route_file))
    monkeypatch.setenv("CI_LLM_KEY", "session-key")
    monkeypatch.setenv("CI_LLM_HEADERS", '{"X-Tenant":"tenant-a"}')

    route = load_routes(_settings())[0]
    key, headers = _resolve_route_secrets(route)

    assert key == "session-key"
    assert headers == {"X-Tenant": "tenant-a"}
    assert "session-key" not in json.dumps(route.public_dict())


@pytest.mark.parametrize("field", ["api_key", "key", "token", "headers"])
def test_headless_route_file_rejects_literal_secrets(
    field: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route_file = tmp_path / "routes.json"
    route_file.write_text(
        json.dumps({"routes": [{"name": "bad", "model": "openai/bad", field: "secret"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("STRIX_ROUTES_FILE", str(route_file))

    with pytest.raises(ValueError, match="literal secrets"):
        load_routes(_settings())


def test_selected_routes_are_validated() -> None:
    save_route(RouteConfig(name="one", model="openai/one"))
    save_route(RouteConfig(name="two", model="openai/two"))

    assert [route.name for route in load_routes(_settings(), selected=["TWO"])] == ["two"]
    with pytest.raises(ValueError, match="unknown selected route"):
        load_routes(_settings(), selected=["missing"])


def test_route_validation_rejects_duplicate_names() -> None:
    routes = [
        RouteConfig(name="Primary", model="openai/one"),
        RouteConfig(name="primary", model="openai/two"),
    ]

    with pytest.raises(ValueError, match="unique"):
        RoutePool(routes, wait_timeout=None)
