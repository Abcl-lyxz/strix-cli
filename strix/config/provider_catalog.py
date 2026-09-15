"""Generated provider/model catalog with runtime adapter discovery.

The checked-in snapshot is data, not executable provider branching.  It is
augmented by LiteLLM's installed adapter inventory and can be atomically
refreshed from models.dev without making normal scan startup network-dependent.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from importlib import import_module, resources
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, cast

import requests

from strix.utils.atomic import atomic_write_text


logger = logging.getLogger(__name__)
CATALOG_URL = "https://models.dev/api.json"
_PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,79}$")


def _cache_path() -> Path:
    configured = os.environ.get("STRIX_PROVIDER_CATALOG", "").strip()
    return (
        Path(configured).expanduser() if configured else Path.home() / ".strix" / "providers.json"
    )


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def _packaged_catalog() -> dict[str, Any]:
    resource = resources.files("strix").joinpath("data/provider_catalog.json")
    value = json.loads(resource.read_text(encoding="utf-8"))
    return cast("dict[str, Any]", value)


def _valid_catalog(value: dict[str, Any]) -> bool:
    providers = value.get("providers")
    return (
        value.get("schema_version") == 1
        and isinstance(providers, list)
        and 0 < len(providers) <= 2_000
        and all(
            isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and _PROVIDER_ID.fullmatch(item["id"])
            for item in providers
        )
    )


def load_provider_catalog() -> dict[str, Any]:
    cached = _read_json(_cache_path())
    if cached is not None and _valid_catalog(cached):
        return cached
    return _packaged_catalog()


def _runtime_provider_ids() -> set[str]:
    try:
        litellm = import_module("litellm")
        raw = getattr(litellm, "provider_list", ()) or ()
        values = {str(item.value if hasattr(item, "value") else item) for item in raw}
    except Exception:  # noqa: BLE001 - catalog fallback must survive optional adapters.
        values = set()
    try:
        discovered = entry_points(group="strix.providers")
    except TypeError:  # pragma: no cover - Python 3.12 has the group API.
        discovered = entry_points().select(group="strix.providers")
    values.update(point.name for point in discovered)
    return {value for value in values if _PROVIDER_ID.fullmatch(value)}


def provider_descriptors(*, include_runtime: bool = True) -> list[dict[str, str]]:
    catalog = load_provider_catalog()
    descriptors: dict[str, dict[str, str]] = {}
    for raw in cast("list[object]", catalog.get("providers", [])):
        if not isinstance(raw, dict):
            continue
        item = {str(key): str(value) for key, value in raw.items() if value is not None}
        descriptors[item["id"]] = item
    runtime_ids = _runtime_provider_ids() if include_runtime else set()
    for provider_id in runtime_ids:
        descriptors.setdefault(
            provider_id,
            {
                "id": provider_id,
                "name": provider_id.replace("_", " ").replace("-", " ").title(),
                "base_url": "",
                "adapter_id": provider_id,
                "transport": "litellm",
                "auth_scheme": "provider-default",
            },
        )
    descriptors.setdefault(
        "custom",
        {
            "id": "custom",
            "name": "Custom endpoint",
            "base_url": "",
            "adapter_id": "openai",
            "transport": "openai",
            "auth_scheme": "bearer",
        },
    )
    return sorted(descriptors.values(), key=lambda item: (item["id"] == "custom", item["name"]))


def recommended_models() -> tuple[str, ...]:
    """Return release-curated model IDs from catalog data, preserving opaque IDs."""
    raw = load_provider_catalog().get("recommended_models")
    if not isinstance(raw, list):
        return ()
    return tuple(value for value in raw if isinstance(value, str) and value.strip())


def adapter_models(provider_id: str) -> list[dict[str, Any]]:
    """List known adapter models without contacting an inference endpoint."""
    found: dict[str, dict[str, Any]] = {}
    models = load_provider_catalog().get("models")
    provider_models = models.get(provider_id) if isinstance(models, dict) else None
    if isinstance(provider_models, dict):
        for model_id, raw in provider_models.items():
            if not isinstance(model_id, str):
                continue
            info = raw if isinstance(raw, dict) else {}
            found[model_id] = {
                "id": model_id,
                "name": str(info.get("name") or model_id),
                "source": "catalog",
                "tools": info.get("tool_call", "unknown"),
            }
    try:
        litellm = import_module("litellm")
        model_cost = getattr(litellm, "model_cost", {})
        if isinstance(model_cost, dict):
            for model_name, raw in model_cost.items():
                if not isinstance(model_name, str) or not isinstance(raw, dict):
                    continue
                if raw.get("litellm_provider") != provider_id:
                    continue
                opaque_id = model_name.removeprefix(f"{provider_id}/")
                found.setdefault(
                    opaque_id,
                    {
                        "id": opaque_id,
                        "name": opaque_id,
                        "source": "adapter",
                        "tools": raw.get("supports_function_calling", "unknown"),
                    },
                )
    except Exception:  # noqa: BLE001 - installed adapter inventory is optional.
        logger.debug("Could not enumerate models for adapter %s", provider_id, exc_info=True)
    return [found[key] for key in sorted(found)[:10_000]]


def _litellm_model_info(candidate: str) -> dict[str, Any] | None:
    try:
        litellm = import_module("litellm")
        return dict(litellm.get_model_info(candidate))
    except Exception:  # noqa: BLE001 - optional adapter metadata is best-effort.
        logger.debug("LiteLLM has no metadata for model %s", candidate, exc_info=True)
        return None


def model_metadata(model: str) -> dict[str, Any]:
    """Return installed metadata without assuming an unknown model is large."""
    provider_id, separator, opaque_model_id = model.partition("/")
    catalog_models = load_provider_catalog().get("models")
    catalog_info: dict[str, Any] | None = None
    if separator and isinstance(catalog_models, dict):
        provider_models = catalog_models.get(provider_id)
        if isinstance(provider_models, dict):
            candidate = provider_models.get(opaque_model_id)
            if isinstance(candidate, dict):
                catalog_info = candidate
    candidates = (model, model.partition("/")[2]) if "/" in model else (model,)
    for candidate in candidates:
        info = _litellm_model_info(candidate)
        if info is None:
            continue
        return {
            "context_window_tokens": int(
                info.get("max_input_tokens") or info.get("max_tokens") or 0
            )
            or 32_768,
            "max_output_tokens": int(info.get("max_output_tokens") or 0) or 8_192,
            "supports_tools": info.get("supports_function_calling"),
            "source": "litellm",
            "confidence": "catalog",
        }
    if catalog_info is not None:
        limits = catalog_info.get("limit")
        limits = limits if isinstance(limits, dict) else {}
        return {
            "context_window_tokens": int(
                limits.get("context") or catalog_info.get("max_input_tokens") or 0
            )
            or 32_768,
            "max_output_tokens": int(
                limits.get("output") or catalog_info.get("max_output_tokens") or 0
            )
            or 8_192,
            "supports_tools": catalog_info.get("tool_call"),
            "source": str(load_provider_catalog().get("source") or "models.dev snapshot"),
            "confidence": "catalog",
        }
    return {
        "context_window_tokens": 32_768,
        "max_output_tokens": 8_192,
        "supports_tools": None,
        "source": "conservative-default",
        "confidence": "unknown",
    }


def refresh_provider_catalog(  # noqa: PLR0912 - validation is deliberately defensive.
    *, force: bool = False, timeout: float = 15.0
) -> dict[str, Any]:
    """Refresh the normalized snapshot, preserving last-known-good on failure."""
    path = _cache_path()
    current = _read_json(path)
    if not force and current and _valid_catalog(current):
        refreshed = current.get("refreshed_at")
        if isinstance(refreshed, str):
            try:
                with_timestamp = datetime.fromisoformat(refreshed.replace("Z", "+00:00"))
            except ValueError:
                with_timestamp = None
            if with_timestamp and datetime.now(UTC) - with_timestamp < timedelta(days=1):
                return {"source": "cache", "path": str(path), "catalog": current}
    headers: dict[str, str] = {"Accept": "application/json"}
    etag = current.get("etag") if current else None
    if isinstance(etag, str):
        headers["If-None-Match"] = etag
    response = requests.get(CATALOG_URL, headers=headers, timeout=timeout, allow_redirects=False)
    if response.status_code == 304 and current is not None:
        return {"source": "cache", "path": str(path), "catalog": current}
    response.raise_for_status()
    if len(response.content) > 25 * 1024 * 1024:
        raise ValueError("models.dev catalog exceeds the 25 MiB safety limit")
    payload = response.json()
    if not isinstance(payload, dict):
        raise TypeError("models.dev returned an invalid catalog")
    providers: list[dict[str, Any]] = []
    models: dict[str, Any] = {}
    for provider_id, raw in payload.items():
        if not isinstance(provider_id, str) or not _PROVIDER_ID.fullmatch(provider_id):
            continue
        if not isinstance(raw, dict):
            continue
        record = raw
        providers.append(
            {
                "id": provider_id,
                "name": str(record.get("name") or provider_id.replace("-", " ").title()),
                "base_url": str(record.get("api") or ""),
                "adapter_id": provider_id,
                "transport": "litellm",
                "auth_scheme": "provider-default",
            }
        )
        if isinstance(record.get("models"), dict):
            models[provider_id] = record["models"]
    normalized = {
        "schema_version": 1,
        "generated_at": str(payload.get("generated_at") or "unknown"),
        "refreshed_at": datetime.now(UTC).isoformat(),
        "etag": response.headers.get("ETag"),
        "source": CATALOG_URL,
        "providers": providers,
        "models": models,
        "recommended_models": list(
            recommended_models()
            or tuple(
                value
                for value in _packaged_catalog().get("recommended_models", [])
                if isinstance(value, str)
            )
        ),
    }
    if not _valid_catalog(normalized):
        raise ValueError("models.dev catalog failed schema validation")
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(normalized, indent=2, ensure_ascii=False))
    return {"source": "network", "path": str(path), "catalog": normalized}


__all__ = [
    "CATALOG_URL",
    "adapter_models",
    "load_provider_catalog",
    "model_metadata",
    "provider_descriptors",
    "recommended_models",
    "refresh_provider_catalog",
]
