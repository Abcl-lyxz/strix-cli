"""Typed settings contract backed exclusively by ``ConfigService``."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

from strix.config.app_config import AppConfig, get_config_service


_SCOPES: dict[str, Literal["immediate", "next_request", "next_scan", "restart"]] = {
    "router": "next_request",
    "scan_defaults": "next_scan",
    "ui.reasoning_effort": "next_request",
    "ui.streaming_enabled": "next_request",
    "ui.prompt_cache": "next_request",
    "ui.llm_timeout_seconds": "next_request",
    "ui.stream_idle_timeout_seconds": "next_request",
    "ui.max_tool_calls_per_turn": "next_request",
    "ui.max_context_images": "next_request",
    "ui.external_editor": "restart",
}


def _field_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    return "text"


def settings_fields() -> list[dict[str, Any]]:
    config = get_config_service().load()
    result: list[dict[str, Any]] = []
    for section in ("router", "scan_defaults", "ui"):
        model = getattr(config, section)
        assert isinstance(model, BaseModel)
        for name in type(model).model_fields:
            value = getattr(model, name)
            identifier = f"{section}.{name}"
            scope = _SCOPES.get(identifier, _SCOPES.get(section, "immediate"))
            result.append(
                {
                    "id": identifier,
                    "label": name.replace("_", " ").capitalize(),
                    "section": section,
                    "value": value,
                    "configured": True,
                    "type": _field_type(value),
                    "source": "app_config_v3",
                    "apply": scope,
                }
            )
    return result


def update_setting(field_id: str, value: Any, *, persist: bool = True) -> dict[str, Any]:
    """Validate and atomically save one setting; v3 settings always persist."""

    del persist
    if "." not in field_id:
        raise ValueError("Unknown setting")
    section, name = field_id.split(".", 1)
    if section not in {"router", "scan_defaults", "ui"}:
        raise ValueError("Unknown setting")
    service = get_config_service()
    current = service.load()
    model = getattr(current, section)
    if name not in type(model).model_fields:
        raise ValueError("Unknown setting")
    validated = type(model).model_validate({**model.model_dump(), name: value})
    updated = current.model_copy(update={section: validated})
    saved: AppConfig = service.save(updated)
    scope = _SCOPES.get(field_id, _SCOPES.get(section, "immediate"))
    return {"saved": True, "apply": scope, "revision": saved.revision, "fields": settings_fields()}


__all__ = ["settings_fields", "update_setting"]
