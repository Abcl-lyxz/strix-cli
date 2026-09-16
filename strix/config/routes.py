"""Persistent and process-only model route configuration."""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from strix.config.loader import config_path, read_config_document, write_config_document
from strix.domain.routes import RouteConfig
from strix.security import get_secret_store


if TYPE_CHECKING:
    from strix.config.settings import Settings


_session_routes: dict[str, RouteConfig] = {}
_session_selected: list[str] | None = None
_session_revision = 0


def session_routes() -> dict[str, RouteConfig]:
    return dict(_session_routes)


def session_revision() -> int:
    return _session_revision


def invalidate_session_routes() -> None:
    global _session_revision  # noqa: PLW0603
    _session_revision += 1


def set_session_route(route: RouteConfig, *, select: bool = True) -> None:
    """Explicit workspace edits take precedence over flags and saved defaults."""
    global _session_selected, _session_revision  # noqa: PLW0603
    _session_routes[route.name.casefold()] = route
    if select:
        _session_selected = [route.name]
    _session_revision += 1


def _object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return cast("dict[str, object]", value)


def _route_dicts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        cast("dict[str, Any]", raw) for raw in cast("list[object]", value) if isinstance(raw, dict)
    ]


def load_routes(settings: Settings, *, selected: list[str] | None = None) -> list[RouteConfig]:
    """Load routes with process-only sources taking deterministic precedence."""
    route_file = os.environ.get("STRIX_ROUTES_FILE", "").strip()
    if route_file:
        routes = _routes_from_file(Path(route_file))
    elif "STRIX_LLM" in os.environ:
        routes = [_legacy_environment_route(settings)]
    else:
        document = read_config_document()
        routing = _object_dict(cast("object", document.get("routing", {})))
        routes = [RouteConfig.from_dict(raw) for raw in _route_dicts(routing.get("routes", []))]
        if not routes and settings.llm.model:
            refs = _object_dict(cast("object", document.get("secret_refs", {})))
            api_ref = refs.get("LLM_API_KEY")
            headers_ref = refs.get("LLM_EXTRA_HEADERS")
            routes = [
                RouteConfig(
                    name="default",
                    model=settings.llm.model,
                    base_url=getattr(settings.llm, "api_base", None),
                    api_key_ref=api_ref if isinstance(api_ref, str) else None,
                    headers_ref=headers_ref if isinstance(headers_ref, str) else None,
                )
            ]
    for name, edited in _session_routes.items():
        routes = [route for route in routes if route.name.casefold() != name]
        routes.append(edited)
    selected = _session_selected if _session_selected is not None else selected
    if selected:
        wanted = {name.casefold() for name in selected}
        routes = [route for route in routes if route.name.casefold() in wanted]
        missing = wanted - {route.name.casefold() for route in routes}
        if missing:
            raise ValueError(f"unknown selected route(s): {', '.join(sorted(missing))}")
    if not any(route.enabled for route in routes):
        raise ValueError("No enabled model routes are configured")
    return routes


def list_saved_routes() -> list[RouteConfig]:
    document = read_config_document()
    routing = _object_dict(cast("object", document.get("routing", {})))
    return [RouteConfig.from_dict(raw) for raw in _route_dicts(routing.get("routes", []))]


def save_route(route: RouteConfig, *, replace: bool = False) -> None:
    document = read_config_document()
    routing = document.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    routes = list_saved_routes()
    index = next(
        (
            i
            for i, existing in enumerate(routes)
            if existing.name.casefold() == route.name.casefold()
        ),
        None,
    )
    if index is None:
        routes.append(route)
    elif replace:
        # Preserve secret references when an edit does not replace them.
        existing = routes[index]
        if route.api_key_ref is None:
            route.api_key_ref = existing.api_key_ref
        if route.headers_ref is None:
            route.headers_ref = existing.headers_ref
        routes[index] = route
    else:
        raise ValueError(f"route already exists: {route.name}")
    routing["strategy"] = "smart"
    routing["routes"] = [item.to_dict() for item in routes]
    document["routing"] = routing
    write_config_document(document)


def remove_route(name: str) -> bool:
    document = read_config_document()
    routing = document.get("routing")
    if not isinstance(routing, dict):
        return False
    routes = list_saved_routes()
    removed = next(
        (route for route in routes if route.name.casefold() == name.casefold()),
        None,
    )
    kept = [route for route in routes if route.name.casefold() != name.casefold()]
    if len(kept) == len(routes):
        return False
    routing["routes"] = [route.to_dict() for route in kept]
    document["routing"] = routing
    write_config_document(document)
    if removed is not None:
        for ref in (removed.api_key_ref, removed.headers_ref):
            if ref:
                with contextlib.suppress(OSError, RuntimeError, ValueError):
                    get_secret_store().delete(ref)
    return True


def set_route_enabled(name: str, enabled: bool) -> bool:
    routes = list_saved_routes()
    target = next((route for route in routes if route.name.casefold() == name.casefold()), None)
    if target is None:
        return False
    target.enabled = enabled
    _replace_all(routes)
    return True


def set_route_key(name: str, value: str) -> str:
    routes = list_saved_routes()
    target = next((route for route in routes if route.name.casefold() == name.casefold()), None)
    if target is None:
        raise ValueError(f"unknown route: {name}")
    ref = target.api_key_ref or f"route.{_slug(target.name)}.api-key"
    store = get_secret_store()
    previous = store.get(ref)
    store.set(ref, value)
    target.api_key_ref = ref
    try:
        _replace_all(routes)
    except Exception:
        with contextlib.suppress(OSError, RuntimeError, ValueError):
            if previous:
                store.set(ref, previous)
            else:
                store.delete(ref)
        raise
    return ref


def delete_route_key(name: str) -> bool:
    routes = list_saved_routes()
    target = next((route for route in routes if route.name.casefold() == name.casefold()), None)
    if target is None or not target.api_key_ref:
        return False
    removed = get_secret_store().delete(target.api_key_ref)
    target.api_key_ref = None
    _replace_all(routes)
    return removed


def routing_strategy() -> str:
    document = read_config_document()
    routing = _object_dict(cast("object", document.get("routing", {})))
    return str(routing.get("strategy") or "smart")


def _replace_all(routes: list[RouteConfig]) -> None:
    document = read_config_document()
    routing = document.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    routing["strategy"] = "smart"
    routing["routes"] = [route.to_dict() for route in routes]
    document["routing"] = routing
    write_config_document(document)


def _routes_from_file(path: Path) -> list[RouteConfig]:
    try:
        data = cast("object", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read STRIX_ROUTES_FILE {path}: {exc}") from exc
    raw_routes = (
        _object_dict(cast("object", data)).get("routes") if isinstance(data, dict) else data
    )
    if not isinstance(raw_routes, list):
        raise TypeError("STRIX_ROUTES_FILE must contain a routes list")
    raw_items = cast("list[object]", raw_routes)
    routes = [RouteConfig.from_dict(raw, allow_env=True) for raw in _route_dicts(raw_items)]
    if len(routes) != len(raw_items):
        raise ValueError("every route entry must be an object")
    return routes


def _legacy_environment_route(settings: Settings) -> RouteConfig:
    key_env = next(
        (name for name in ("LLM_API_KEY", "OPENAI_API_KEY") if name in os.environ),
        None,
    )
    headers_env = "LLM_EXTRA_HEADERS" if "LLM_EXTRA_HEADERS" in os.environ else None
    return RouteConfig(
        name="environment",
        model=(settings.llm.model or "").strip(),
        base_url=getattr(settings.llm, "api_base", None),
        api_key_env=key_env,
        headers_env=headers_env,
    )


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "-" for char in value.lower())


__all__ = [
    "config_path",
    "delete_route_key",
    "list_saved_routes",
    "load_routes",
    "remove_route",
    "routing_strategy",
    "save_route",
    "set_route_enabled",
    "set_route_key",
]
