"""Read-model projectors shared by the framed TUI and viewer transports."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from strix.config import load_settings
from strix.config.models import is_recommended_or_frontier_model
from strix.config.routes import load_routes
from strix.interface.presentation import is_subscription_run
from strix.interface.tui.backend.projection import (
    MAX_TERMINAL_EVENTS,
    MAX_TERMINAL_VULNERABILITIES,
    bounded_state_projection,
    collection_item_projection,
    terminal_projection,
)


_LLM_ENV_ALIASES = frozenset(
    {
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "OLLAMA_API_BASE",
        "STRIX_REASONING_EFFORT",
    }
)


def display_api_base(value: str) -> str:
    """Project an API URL without query, fragment, or embedded credentials."""

    if not value:
        return ""
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        return ""
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    with contextlib.suppress(ValueError):
        if parsed.port is not None:
            host += f":{parsed.port}"
    return f"{parsed.scheme}://{host}{parsed.path}"


class WorkspaceProjector:
    """Normalize mutable application state into protocol-v7 read models."""

    def snapshot(self, source: Any) -> dict[str, Any]:
        model = ""
        api_key_configured = False
        api_base = ""
        reasoning_effort = "high"
        streaming_enabled = True
        prompt_cache = True
        llm_timeout = 300
        max_tool_calls_per_turn = 32
        max_context_images = 3
        editor_command = ""
        with contextlib.suppress(Exception):
            settings = load_settings()
            editor_command = (
                getattr(getattr(settings, "keyboard", None), "external_editor", None) or ""
            )
            model = (settings.llm.model or "").strip()
            api_key_configured = bool((settings.llm.api_key or "").strip())
            api_base = display_api_base((settings.llm.api_base or "").strip())
            reasoning_effort = settings.llm.reasoning_effort
            streaming_enabled = not settings.llm.disable_streaming
            prompt_cache = settings.llm.prompt_cache
            llm_timeout = settings.llm.timeout
            max_tool_calls_per_turn = settings.llm.max_tool_calls_per_turn
            max_context_images = settings.runtime.max_context_images
            routes = load_routes(
                settings,
                selected=[source.selected_route] if source.selected_route else None,
            )
            if routes:
                selected = routes[0]
                model = selected.model
                api_key_configured = bool(
                    selected.api_key_ref or selected.api_key_env or settings.llm.api_key
                )
                api_base = display_api_base(selected.base_url or "")
        usage = (
            dict(source.report_state.get_total_llm_usage())
            if source.report_state is not None
            else {}
        )
        subscription = False
        with contextlib.suppress(Exception):
            subscription = is_subscription_run(source.report_state)
        model_warning = ""
        if model and not is_recommended_or_frontier_model(model):
            model_warning = (
                f"{model} is not a recommended frontier model. Pentest quality could be degraded."
            )
        route_health: list[dict[str, Any]] = []
        route_pool = source.scan_context.route_pool if source.scan_context is not None else None
        if route_pool is not None:
            with contextlib.suppress(Exception):
                route_health = route_pool.public_status()[:32]
        state = {
            "setup_mode": source.setup_mode,
            "scan_started": source.scan_started,
            "scan_state": source.scan_state,
            "targets": [
                terminal_projection(target, max_string=128) for target in source.targets[:16]
            ],
            "target_ids": [source.target_id(target) for target in source.targets[:16]],
            "target_count": len(source.targets),
            "working_dir": str(Path.cwd()),
            "pending_mount": source.pending_workspace_mount or "",
            "instruction": terminal_projection(source.instruction, max_string=2 * 1024),
            "scan_mode": source.scan_mode,
            "max_budget_usd": source.max_budget_usd,
            "max_turns": source.max_turns,
            "max_agents": source.max_agents,
            "scope_mode": source.scope_mode,
            "diff_base": terminal_projection(source.diff_base, max_string=256),
            "model": terminal_projection(model, max_string=256),
            "model_warning": terminal_projection(model_warning, max_string=512),
            "api_key_configured": api_key_configured,
            "api_base": terminal_projection(api_base, max_string=512),
            "reasoning_effort": reasoning_effort,
            "streaming_enabled": streaming_enabled,
            "prompt_cache": prompt_cache,
            "llm_timeout": llm_timeout,
            "max_tool_calls_per_turn": max_tool_calls_per_turn,
            "max_context_images": max_context_images,
            "config_env_override": any(alias in os.environ for alias in _LLM_ENV_ALIASES),
            "selected_route": terminal_projection(source.selected_route, max_string=128),
            "notification_unread": source.notification_service.unread_count(),
            "caido_url": terminal_projection(
                getattr(source.report_state, "caido_url", None), max_string=1024
            ),
            "messages": [
                {
                    "id": str(message.get("id", ""))[:64],
                    "text": terminal_projection(message.get("text", ""), max_string=256),
                    "level": str(message.get("level", "info"))[:32],
                }
                for message in source.messages[-10:]
            ],
            "usage": terminal_projection(usage, max_string=256, max_items=20),
            "route_health": terminal_projection(route_health, max_string=512, max_items=32),
            "subscription": subscription,
            "connections": [
                {
                    "name": terminal_projection(entry["name"], max_string=64),
                    "tool_count": entry["tool_count"],
                    "dead": entry["dead"],
                }
                for entry in source.mcp_connections[:32]
            ],
            "viewer_status": source.viewer_status,
            "viewer_url": terminal_projection(source.viewer_url, max_string=1024),
            "error": terminal_projection(
                source.error
                or (
                    getattr(source.report_state, "run_record", {}).get("storage_error")
                    if source.report_state
                    else None
                ),
                max_string=2 * 1024,
            ),
            "attachments": terminal_projection(source.workspace.public_attachments()),
            "recovery": terminal_projection(source.recovery),
            "editor_command": editor_command,
            "recent_runs": source.workspace.recent_sessions() if source.setup_mode else [],
        }
        return bounded_state_projection(state)

    def collection(self, source: Any, name: str) -> list[dict[str, Any]]:
        if name == "agents":
            return [
                {
                    key: terminal_projection(agent.get(key), max_string=256, max_items=5)
                    for key in (
                        "id",
                        "name",
                        "parent_id",
                        "status",
                        "wait_kind",
                        "error_message",
                        "created_at",
                        "updated_at",
                    )
                    if key in agent
                }
                for agent in source.live_view.agents.values()
            ]
        if name == "events":
            return [collection_item_projection(event) for event in source.live_view.events]
        if name == "vulnerabilities":
            reports = (
                source.report_state.vulnerability_reports
                if source.report_state is not None
                else []
            )[-MAX_TERMINAL_VULNERABILITIES:]
            result: list[dict[str, Any]] = []
            for index, report in enumerate(reports):
                projected = collection_item_projection(report)
                report_id = projected.get("id")
                if not isinstance(report_id, str) or not report_id:
                    projected["id"] = f"vulnerability-{index}"
                result.append(projected)
            return result
        raise ValueError(f"Unknown collection: {name}")

    def collection_snapshot(
        self, source: Any, name: str
    ) -> tuple[int | None, list[dict[str, Any]]]:
        if name == "events":
            cursor, events = source.live_view.event_snapshot(limit=MAX_TERMINAL_EVENTS)
            return cursor, [collection_item_projection(event) for event in events]
        return None, self.collection(source, name)

    def collection_changes(
        self, source: Any, name: str, cursor: int
    ) -> tuple[int, list[dict[str, Any]]]:
        if name != "events":
            raise ValueError(f"Collection {name!r} does not expose incremental changes")
        next_cursor, events = source.live_view.event_changes_since(cursor)
        return next_cursor, [
            collection_item_projection(event) for event in events[-MAX_TERMINAL_EVENTS:]
        ]
