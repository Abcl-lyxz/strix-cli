"""Validated MCP forms backed by the existing local connection loader."""

from __future__ import annotations

import json
from typing import Any, cast
from uuid import uuid4

from strix.security import get_secret_store
from strix.tools.mcp import loader
from strix.tools.mcp.config import McpConnectionConfig
from strix.utils.secret_files import write_secret_text


def connections() -> list[dict[str, Any]]:
    return [
        {
            "name": c.name,
            "transport": c.transport,
            "url": c.url,
            "command": c.command,
            "args": json.dumps(c.args),
            "configured": bool(c.auth),
        }
        for c in loader.load_user_mcp_configs()
    ]


def update_connection(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise ValueError("Enter a connection name")
    existing = next((c for c in loader.load_user_mcp_configs() if c.name == name), None)
    values = existing.model_dump() if existing else {}
    for field in ("name", "transport", "url", "command", "args"):
        if field in payload:
            value = payload[field]
            if field == "args" and isinstance(value, str):
                value = json.loads(value or "[]")
            values[field] = value or ([] if field == "args" else None)
    token = payload.get("token")
    ref = f"mcp.{name}.{uuid4().hex}.bearer"
    if token:
        values["auth"] = {"kind": "bearer", "token": token, "secret_ref": ref}
    configured = McpConnectionConfig.model_validate(values)
    if token:
        get_secret_store().set(ref, str(token))
    if payload.get("persist") is True:
        path = loader.config_path()
        raw: Any = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        if not isinstance(raw, list):
            raise TypeError("MCP configuration must be a list")
        saved = configured.model_dump(exclude_none=True)
        if saved.get("auth", {}).get("secret_ref"):
            saved["auth"].pop("token", None)
        write_secret_text(
            path,
            json.dumps(
                [
                    c
                    for c in cast("list[object]", raw)
                    if not isinstance(c, dict) or cast("dict[str, Any]", c).get("name") != name
                ]
                + [saved],
                indent=2,
            ),
        )
    loader.set_session_config(configured)
    return {"connections": connections(), "apply": "next scan"}
