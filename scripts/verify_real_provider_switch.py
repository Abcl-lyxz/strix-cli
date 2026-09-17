"""Release-only smoke test against two real provider accounts.

The workflow supplies secrets.  This script deliberately prints provider IDs
only, never credentials, endpoints, model responses, or request bodies.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing

from strix.config.app_config import AppConfig, ConfigService, UiPreferences, set_config_service
from strix.domain.routes import RouteConfig
from strix.routing import RoutePool


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"release provider smoke requires {name}")
    return value


def _route(label: str, revision: int) -> RouteConfig:
    provider = _required(f"STRIX_RELEASE_PROVIDER_{label}_ID")
    model = _required(f"STRIX_RELEASE_PROVIDER_{label}_MODEL")
    base_url = os.environ.get(f"STRIX_RELEASE_PROVIDER_{label}_BASE_URL", "").strip()
    return RouteConfig(
        name=f"release-{label.lower()}",
        model=model,
        provider_id=provider,
        model_id=model.split("/", 1)[-1],
        adapter_id=model.split("/", 1)[0],
        base_url=base_url or None,
        api_key_env=f"STRIX_RELEASE_PROVIDER_{label}_API_KEY",
        connection_revision=revision,
        quality_tier="strong",
        supports_tools=True,
        supports_vision=False,
        supports_reasoning=False,
        context_window_tokens=16_384,
        max_output_tokens=256,
        metadata_source="release-secret",
        metadata_confidence="verified",
    )


def _request(text: str) -> dict[str, Any]:
    return {
        "system_instructions": "Reply with OK only.",
        "input": text,
        "model_settings": ModelSettings(max_tokens=8),
        "tools": [],
        "output_schema": None,
        "handoffs": [],
        "tracing": ModelTracing.DISABLED,
        "previous_response_id": None,
        "conversation_id": None,
        "prompt": None,
    }


async def _main() -> None:
    first = _route("A", 1)
    second = _route("B", 2)
    if first.provider_id == second.provider_id:
        raise RuntimeError("release provider smoke requires two distinct provider IDs")
    revision = {"value": 1}
    routes = {1: first, 2: second}
    with tempfile.TemporaryDirectory(prefix="strix-release-provider-") as directory:
        service = ConfigService(Path(directory) / "config.json")
        service.save(
            AppConfig(
                ui=UiPreferences(reasoning_effort="none", streaming_enabled=False),
            )
        )
        set_config_service(service)
        pool = RoutePool(
            [first],
            wait_timeout=30,
            route_reloader=lambda: (revision["value"], [routes[revision["value"]]]),
        )
        try:
            await pool.get_response(**_request("provider A connectivity check"))
            revision["value"] = 2
            await pool.get_response(**_request("provider B connectivity check"))
        finally:
            await pool.close()
            set_config_service(None)
    sys.stdout.write(f"real provider switch passed: {first.provider_id} -> {second.provider_id}\n")


if __name__ == "__main__":
    asyncio.run(_main())
