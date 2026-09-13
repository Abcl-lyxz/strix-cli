"""One validated settings form contract for terminal and browser clients."""

from __future__ import annotations

import os
from typing import Any, cast

from pydantic import AliasChoices, BaseModel

from strix.config import loader


def settings_fields() -> list[dict[str, Any]]:
    settings = loader.load_settings()
    result: list[dict[str, Any]] = []
    saved = loader.read_config_document().get("env", {})
    for section in ("llm", "dedupe", "runtime", "context", "routing", "integrations", "keyboard"):
        model = cast("BaseModel", getattr(settings, section))
        for name, field in type(model).model_fields.items():
            alias = field.validation_alias or field.alias or name
            aliases = (
                [str(item) for item in alias.choices if isinstance(item, str)]
                if isinstance(alias, AliasChoices)
                else [str(alias)]
            )
            alias = str(aliases[0])
            value = getattr(model, name)
            secret = any(word in name for word in ("key", "headers"))
            result.append(
                {
                    "id": f"{section}.{name}",
                    "label": name.replace("_", " ").capitalize(),
                    "section": section,
                    "alias": alias,
                    "secret": secret,
                    "value": "" if secret else value,
                    "configured": bool(value),
                    "type": "secret"
                    if secret
                    else "boolean"
                    if isinstance(value, bool)
                    else "number"
                    if isinstance(value, int)
                    else "text",
                    "source": "session"
                    if name in loader.session_fields().get(section, {})
                    else "environment"
                    if any(a in os.environ for a in aliases)
                    else "saved"
                    if any(a in saved for a in aliases)
                    else "default",
                    "apply": "next scan"
                    if section in {"runtime", "integrations"}
                    else "next request",
                }
            )
    return result


def update_setting(field_id: str, value: Any, *, persist: bool = False) -> dict[str, Any]:
    field = next((f for f in settings_fields() if f["id"] == field_id), None)
    if field is None:
        raise ValueError("Unknown setting")
    section, name = field_id.split(".", 1)
    current = cast("BaseModel", getattr(loader.load_settings(), section))
    # Validate through the existing model, rather than a second UI-specific schema.
    updated = type(current).model_validate({**current.model_dump(), name: value})
    value = getattr(updated, name)
    if persist:
        loader.persist_overrides({field["alias"]: value})
    loader.set_session_field(section, name, value)
    if section in {"llm", "routing"}:
        from strix.config import routes  # noqa: PLC0415

        routes.invalidate_session_routes()
    return {"saved": persist, "apply": field["apply"], "fields": settings_fields()}
