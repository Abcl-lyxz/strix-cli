"""Provider identity, discovery, and guided connection setup for both clients."""

from __future__ import annotations

import hashlib
import time
from dataclasses import replace
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import uuid4

import requests

from strix.config import routes as route_config
from strix.config.routes import list_saved_routes, save_route, set_session_route
from strix.routing import RouteConfig
from strix.security import get_secret_store, redact_secrets
from strix.security.secrets import register_secret


PROVIDERS = [
    {
        "id": "tokenrouter",
        "name": "TokenRouter",
        "base_url": "https://api.tokenrouter.com/v1",
        "prefix": "openai",
    },
    {
        "id": "openrouter",
        "name": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1",
        "prefix": "openrouter",
    },
    {"id": "openai", "name": "OpenAI", "base_url": "https://api.openai.com/v1", "prefix": "openai"},
    {
        "id": "anthropic",
        "name": "Anthropic",
        "base_url": "https://api.anthropic.com/v1",
        "prefix": "anthropic",
    },
    {
        "id": "gemini",
        "name": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "prefix": "gemini",
    },
    {"id": "ollama", "name": "Ollama", "base_url": "http://localhost:11434/v1", "prefix": "openai"},
    {"id": "custom", "name": "Custom OpenAI-compatible", "base_url": "", "prefix": "openai"},
]
_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def provider_descriptor(provider_id: str) -> dict[str, str]:
    for provider in PROVIDERS:
        if provider["id"] == provider_id:
            return dict(provider)
    raise ValueError("Unknown provider")


def identify_provider(route: RouteConfig) -> dict[str, str]:
    if route.provider_id:
        return provider_descriptor(route.provider_id)
    host = urlsplit(route.base_url or "").hostname
    for provider in PROVIDERS:
        if host and host == urlsplit(provider["base_url"]).hostname:
            return dict(provider)
    if host:
        return provider_descriptor("custom")
    prefix = route.model.split("/", 1)[0]
    return next((dict(p) for p in PROVIDERS if p["id"] == prefix), provider_descriptor("custom"))


def profile_list() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    routes = {r.name.casefold(): r for r in list_saved_routes()}
    routes.update(route_config.session_routes())
    for route in routes.values():
        provider = identify_provider(route)
        result.append(
            {
                **route.public_dict(),
                "provider_id": provider["id"],
                "provider_name": provider["name"],
                "model_id": route.model_id or route.model.partition("/")[2] or route.model,
                "transport": route.transport or provider["prefix"],
            }
        )
    return result


def validate_endpoint(endpoint: str) -> str:
    parts = urlsplit(endpoint.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Base URL must be an absolute HTTP or HTTPS URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(
            "Put credentials in the API key field; base URLs cannot contain "
            "credentials, query strings, or fragments"
        )
    return endpoint.strip().rstrip("/")


def discover_models(  # noqa: PLR0912 - provider transports share one bounded discovery pipeline
    provider_id: str,
    *,
    base_url: str = "",
    api_key: str = "",
    profile: str = "",
    refresh: bool = False,
) -> dict[str, Any]:
    provider = provider_descriptor(provider_id)
    if profile:
        route = route_config.session_routes().get(profile.casefold()) or next(
            (r for r in list_saved_routes() if r.name == profile), None
        )
        if route is None:
            raise ValueError("Provider connection not found")
        base_url = base_url or route.base_url or ""
        if not api_key and route.api_key_ref:
            api_key = get_secret_store().get(route.api_key_ref) or ""
    endpoint = validate_endpoint(base_url or provider["base_url"])
    cache_key = hashlib.sha256(f"{provider_id}:{endpoint}:{api_key}".encode()).hexdigest()
    cached = _cache.get(cache_key)
    if cached and not refresh and time.monotonic() - cached[0] < 3600:
        return {"models": cached[1], "source": "cache"}
    register_secret(api_key)
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    if provider_id == "anthropic":
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    elif provider_id == "gemini":
        headers = {"x-goog-api-key": api_key}
    try:
        response = requests.get(
            endpoint + "/models", headers=headers, timeout=10, allow_redirects=False
        )
        response.raise_for_status()
        raw_payload: object = response.json()
        if not isinstance(raw_payload, dict):
            raise TypeError("Model endpoint returned an invalid response")  # noqa: TRY301
        payload = cast("dict[str, Any]", raw_payload)
        values: object = payload.get("data", payload.get("models", []))
        if not isinstance(values, list):
            raise TypeError("Model endpoint returned an invalid model list")  # noqa: TRY301
        models: list[dict[str, Any]] = []
        for raw_entry in cast("list[object]", values)[:10000]:
            if not isinstance(raw_entry, dict):
                continue
            entry = cast("dict[str, Any]", raw_entry)
            model_id = entry.get("id") or entry.get("name")
            if isinstance(model_id, str) and model_id:
                models.append(
                    {
                        "id": model_id,
                        "name": entry.get("display_name") or model_id,
                        "source": "discovered",
                        "tools": "unknown",
                    }
                )
        _cache[cache_key] = (time.monotonic(), models)
        while len(_cache) > 100:
            _cache.pop(next(iter(_cache)))
        return {"models": models, "source": "discovered"}  # noqa: TRY300 - bounded discovery pipeline
    except (requests.RequestException, ValueError, TypeError) as exc:
        configured = [
            {"id": r["model_id"], "source": "configured", "tools": "unknown"}
            for r in profile_list()
            if r["provider_id"] == provider_id
        ]
        return {
            "models": cached[1] if cached else configured,
            "source": "cache" if cached else "configured" if configured else "manual",
            "error": redact_secrets(str(exc)),
            "manual_allowed": True,
        }


def connect_provider(payload: dict[str, Any]) -> dict[str, Any]:
    provider = provider_descriptor(str(payload.get("provider_id", "custom")))
    endpoint = validate_endpoint(str(payload.get("base_url") or provider["base_url"]))
    model_id = str(payload.get("model_id") or "").strip()
    if not model_id:
        raise ValueError("Choose a model or enter its exact model ID")
    name = str(payload.get("name") or provider["id"]).strip()
    prefix = provider["prefix"]
    # API model IDs are opaque; only the SDK routing prefix is added.
    existing = route_config.session_routes().get(name.casefold()) or next(
        (r for r in list_saved_routes() if r.name.casefold() == name.casefold()), None
    )
    route = (
        replace(existing, model=f"{prefix}/{model_id}", base_url=endpoint)
        if existing
        else RouteConfig(name=name, model=f"{prefix}/{model_id}", base_url=endpoint)
    )
    route.provider_id = provider["id"]
    route.transport = prefix
    route.model_id = model_id
    api_key = payload.get("api_key")
    previous = None
    ref = f"route.{uuid4().hex}.api-key"
    store = get_secret_store()
    changed_key = isinstance(api_key, str) and bool(api_key.strip())
    if changed_key:
        previous = store.get(ref)
        store.set(ref, str(api_key).strip())
        route.api_key_ref = ref
        route.api_key_env = None
    try:
        if payload.get("persist") is True:
            save_route(route, replace=True)
        set_session_route(route)
    except Exception:
        if changed_key:
            if previous is not None:
                store.set(ref, previous)
            else:
                store.delete(ref)
        raise
    return {"connected": True, "name": name, "profiles": profile_list()}


def update_route_options(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").casefold()
    routes = {route.name.casefold(): route for route in list_saved_routes()}
    routes.update(route_config.session_routes())
    if name not in routes:
        raise ValueError("Choose an existing model connection")
    changes: dict[str, Any] = {}
    for field in ("priority", "max_concurrency", "rpm", "tpm"):
        if field not in payload:
            continue
        value = payload[field]
        if value is None and field in {"rpm", "tpm"}:
            changes[field] = None
        elif not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{field} must be a positive whole number")
        else:
            changes[field] = value
    if "enabled" in payload:
        if not isinstance(payload["enabled"], bool):
            raise ValueError("enabled must be true or false")
        changes["enabled"] = payload["enabled"]
    updated = replace(routes[name], **changes)
    if payload.get("persist") is True:
        save_route(updated, replace=True)
    set_session_route(updated, select=False)
    return {"profiles": profile_list(), "apply": "next request"}
