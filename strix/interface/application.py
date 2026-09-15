"""UI-independent state and command controller for interactive Strix clients."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import math
import os
import webbrowser
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from strix.config import load_settings
from strix.config import routes as route_config
from strix.config.models import is_recommended_or_frontier_model
from strix.config.routes import (
    list_saved_routes,
    load_routes,
    save_route,
    set_session_route,
)
from strix.config.settings import DEFAULT_MAX_AGENTS, DEFAULT_MAX_TURNS
from strix.config.ui import settings_fields, update_setting
from strix.core.paths import runtime_state_dir
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.backend.projection import (
    MAX_TERMINAL_EVENTS,
    MAX_TERMINAL_VULNERABILITIES,
    SCAN_MODES,
    SCOPE_MODES,
    bounded_state_projection,
    collection_item_projection,
    sanitize_terminal_text,
    terminal_projection,
)
from strix.interface.utils import is_subscription_run
from strix.interface.workspace import WorkspaceCommands
from strix.notifications import Notification, get_notification_service
from strix.routing import RouteConfig
from strix.security import get_secret_store
from strix.tools.workspace_search import search_local_workspace


if TYPE_CHECKING:
    import argparse

    from strix.report.state import ReportState


_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})
_REASONING_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max"})
_MAX_PROMPT_BYTES = 256 * 1024
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

ChangeCallback = Callable[[], None]
StartCallback = Callable[[], Awaitable[None]]
VerifyCallback = Callable[[], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]


class ApplicationController:
    """Own setup state and expose serializable scan state to any TUI."""

    def __init__(
        self,
        args: argparse.Namespace,
        *,
        live_view: TuiLiveView | None = None,
        coordinator: Any = None,
        report_state: ReportState | None = None,
        on_start: StartCallback | None = None,
        on_verify: VerifyCallback | None = None,
        on_quit: QuitCallback | None = None,
        on_change: ChangeCallback | None = None,
    ) -> None:
        self.args = args
        self.workspace = WorkspaceCommands(self)
        self.live_view = live_view or TuiLiveView()
        self.coordinator = coordinator
        self.report_state = report_state
        self.scan_loop: asyncio.AbstractEventLoop | None = None
        self.setup_mode = bool(args.needs_setup)
        self.scan_started = not self.setup_mode
        self._start_in_progress = False
        self.scan_state = "setup" if self.setup_mode else "running"
        self.targets = [
            str(target["original"])
            for target in args.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        instruction = args.instruction
        self.instruction = instruction.strip() if isinstance(instruction, str) else ""
        requested_scan_mode = str(args.scan_mode)
        self.scan_mode = requested_scan_mode if requested_scan_mode in SCAN_MODES else "deep"
        raw_budget = args.max_budget_usd
        self.max_budget_usd = (
            float(raw_budget)
            if isinstance(raw_budget, int | float)
            and not isinstance(raw_budget, bool)
            and math.isfinite(float(raw_budget))
            and raw_budget > 0
            else None
        )
        raw_turns = args.max_turns
        self.max_turns = (
            raw_turns
            if isinstance(raw_turns, int) and not isinstance(raw_turns, bool) and raw_turns > 0
            else DEFAULT_MAX_TURNS
        )
        raw_agents = getattr(args, "max_agents", DEFAULT_MAX_AGENTS)
        self.max_agents = (
            raw_agents
            if isinstance(raw_agents, int) and not isinstance(raw_agents, bool) and raw_agents >= 2
            else DEFAULT_MAX_AGENTS
        )
        requested_scope = str(args.scope_mode)
        self.scope_mode = requested_scope if requested_scope in SCOPE_MODES else "auto"
        raw_diff_base = args.diff_base
        self.diff_base = raw_diff_base.strip() if isinstance(raw_diff_base, str) else None
        # Host directory mounted for the agent to work in when the scan has no
        # target, set only once the user confirms it. It is a workspace, not a
        # target: it carries no scan scope, and the instruction is the only
        # source of truth for what to do.
        self.workspace_mount: str | None = None
        # A target-less launch enters the live view and asks there before
        # anything is prepared; this holds the directory awaiting that answer.
        self.pending_workspace_mount: str | None = None
        self.messages: list[dict[str, str]] = []
        self._next_message_id = 1
        self.error: str | None = None
        # The run's MCP connection roster (name / tool_count / dead), pushed by
        # the engine via the mcp_status_sink once the connections are established
        # and again each time one dies. Empty for a run with no MCP connections,
        # so the Go sidebar simply omits the panel. Non-secret by construction.
        self.mcp_connections: list[dict[str, Any]] = []
        self.viewer_status = "idle"
        self.viewer_url: str | None = None
        self._viewer_httpd: Any = None
        self._on_start = on_start
        self._on_verify = on_verify
        self._on_quit = on_quit
        self._on_change = on_change
        requested_routes = getattr(args, "route", None) or []
        self.selected_route = str(requested_routes[0]) if requested_routes else ""
        self.recovery: dict[str, Any] = {}
        self.notification_service = get_notification_service()
        self._unsubscribe_notifications = self.notification_service.subscribe(self._on_notification)

    def _on_notification(self, notification: Notification) -> None:
        """Surface actionable global events while retaining every event in the inbox."""
        if self.scan_loop is not None and self.scan_loop.is_running():
            try:
                current = asyncio.get_running_loop()
            except RuntimeError:
                current = None
            if current is not self.scan_loop:
                self.scan_loop.call_soon_threadsafe(self._on_notification, notification)
                return
        if notification.event_type.startswith(
            ("model.", "runtime.route.", "security.credential", "agent.failed")
        ):
            self.recovery = (
                {}
                if notification.event_type.endswith("recovered")
                else {
                    "state": notification.event_type,
                    "title": notification.title,
                    "detail": notification.detail,
                    "agent_id": notification.agent_id,
                }
            )
        if self.notification_service.should_surface(notification):
            detail = f": {notification.detail}" if notification.detail else ""
            self._append_message(
                f"{notification.title}{detail}",
                "error"
                if notification.severity in {"error", "critical"}
                else notification.severity,
            )
        if self.scan_loop is not None and self.scan_loop.is_running():
            self.scan_loop.call_soon_threadsafe(self.notify_changed)
        else:
            self.notify_changed()

    def set_change_callback(self, callback: ChangeCallback) -> None:
        self._on_change = callback

    def record_output(self, text: str) -> None:
        """Persist incidental stdout/stderr without painting it into the TUI.

        Python tracebacks and dependency diagnostics are useful in the local
        event log, but each physical line used to become a setup notification.
        That made expected provider failures look like Python source code and
        repeatedly reflowed the full-screen interface. User-facing failures
        already travel through typed controller messages and state errors.
        """
        try:
            self.notification_service.record_output(
                text, run_id=getattr(self.args, "run_name", None)
            )
        except Exception:  # noqa: BLE001 - a diagnostic failure must not recurse through stderr
            self.add_message("Cannot save local output diagnostics", "error")

    def notify_changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    def set_runtime(
        self,
        *,
        report_state: ReportState | None = None,
        scan_loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if report_state is not None:
            self.report_state = report_state
        if scan_loop is not None:
            self.scan_loop = scan_loop

    def set_mcp_connections(self, roster: list[dict[str, Any]]) -> None:
        """Store the run's MCP connection roster and repaint.

        ``roster`` is the engine's non-secret status snapshot: one entry per
        connection carrying ``name``, ``tool_count``, and ``dead``. Called once
        when the connections are established (all healthy) and again whenever a
        connection dies (the same whole-roster snapshot, with that one now dead)."""
        self.mcp_connections = [
            {
                "name": str(entry.get("name", "")),
                "tool_count": int(entry.get("tool_count", 0) or 0),
                "dead": bool(entry.get("dead", False)),
            }
            for entry in roster
            if isinstance(entry, dict) and entry.get("name")
        ]
        self.notify_changed()

    def begin_preparation(self) -> None:
        """Mark a directly-launched run as preparing behind the live TUI."""
        self.scan_state = "preparing"
        self.notify_changed()

    def fail_preparation(self, detail: str) -> None:
        self.scan_state = "failed"
        self.error = detail
        self.notify_changed()

    def add_message(self, text: str, level: str = "info") -> None:
        self._append_message(text, level)
        self.notify_changed()

    def _append_message(self, text: str, level: str) -> None:
        self.messages.append(
            {
                "id": f"message-{self._next_message_id}",
                "text": sanitize_terminal_text(text),
                "level": sanitize_terminal_text(level),
            }
        )
        self._next_message_id += 1
        self.messages = self.messages[-200:]

    def snapshot(self) -> dict[str, Any]:
        """Return small mutable state; histories are streamed as collections."""
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
            api_base = _display_api_base((settings.llm.api_base or "").strip())
            reasoning_effort = settings.llm.reasoning_effort
            streaming_enabled = not settings.llm.disable_streaming
            prompt_cache = settings.llm.prompt_cache
            llm_timeout = settings.llm.timeout
            max_tool_calls_per_turn = settings.llm.max_tool_calls_per_turn
            max_context_images = settings.runtime.max_context_images
            routes = load_routes(
                settings, selected=[self.selected_route] if self.selected_route else None
            )
            if routes:
                selected = routes[0]
                model = selected.model
                api_key_configured = bool(
                    selected.api_key_ref or selected.api_key_env or settings.llm.api_key
                )
                api_base = _display_api_base(selected.base_url or "")
        usage: dict[str, Any] = {}
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
        subscription = False
        with contextlib.suppress(Exception):
            subscription = is_subscription_run(self.report_state)
        model_warning = ""
        if model and not is_recommended_or_frontier_model(model):
            model_warning = (
                f"{model} is not a recommended frontier model. Pentest quality could be degraded."
            )
        route_health: list[dict[str, Any]] = []
        if self.report_state is not None:
            get_run_dir = getattr(self.report_state, "get_run_dir", None)
            if callable(get_run_dir):
                path = runtime_state_dir(get_run_dir()) / "routes.json"
                with contextlib.suppress(OSError, ValueError, TypeError):
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(payload, dict) and isinstance(payload.get("routes"), list):
                        route_health = payload["routes"][:32]
        state = {
            "setup_mode": self.setup_mode,
            "scan_started": self.scan_started,
            "scan_state": self.scan_state,
            "targets": [
                terminal_projection(target, max_string=128) for target in self.targets[:16]
            ],
            "target_ids": [self.target_id(target) for target in self.targets[:16]],
            "target_count": len(self.targets),
            "working_dir": str(Path.cwd()),
            "pending_mount": self.pending_workspace_mount or "",
            "instruction": terminal_projection(self.instruction, max_string=2 * 1024),
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_turns": self.max_turns,
            "max_agents": self.max_agents,
            "scope_mode": self.scope_mode,
            "diff_base": terminal_projection(self.diff_base, max_string=256),
            "model": terminal_projection(model, max_string=256),
            "model_warning": terminal_projection(model_warning, max_string=512),
            # Credentials are write-only over the TUI protocol.  A snapshot
            # reveals presence, never the key itself.
            "api_key_configured": api_key_configured,
            "api_base": terminal_projection(api_base, max_string=512),
            "reasoning_effort": reasoning_effort,
            "streaming_enabled": streaming_enabled,
            "prompt_cache": prompt_cache,
            "llm_timeout": llm_timeout,
            "max_tool_calls_per_turn": max_tool_calls_per_turn,
            "max_context_images": max_context_images,
            "config_env_override": any(alias in os.environ for alias in _LLM_ENV_ALIASES),
            "selected_route": terminal_projection(self.selected_route, max_string=128),
            "notification_unread": self.notification_service.unread_count(),
            "caido_url": terminal_projection(
                getattr(self.report_state, "caido_url", None), max_string=1024
            ),
            "messages": [
                {
                    "id": str(message.get("id", ""))[:64],
                    "text": terminal_projection(message.get("text", ""), max_string=256),
                    "level": str(message.get("level", "info"))[:32],
                }
                for message in self.messages[-10:]
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
                for entry in self.mcp_connections[:32]
            ],
            "viewer_status": self.viewer_status,
            "viewer_url": terminal_projection(self.viewer_url, max_string=1024),
            "error": terminal_projection(
                self.error
                or (
                    getattr(self.report_state, "run_record", {}).get("storage_error")
                    if self.report_state
                    else None
                ),
                max_string=2 * 1024,
            ),
            "attachments": terminal_projection(self.workspace.public_attachments()),
            "recovery": terminal_projection(self.recovery),
            "editor_command": editor_command,
            "recent_runs": self.workspace.recent_sessions() if self.setup_mode else [],
        }
        return bounded_state_projection(state)

    def collection(self, name: str) -> list[dict[str, Any]]:
        """Return one bounded terminal projection with stable item identities."""
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
                for agent in self.live_view.agents.values()
            ]
        if name == "events":
            return [collection_item_projection(event) for event in self.live_view.events]
        if name == "vulnerabilities":
            reports = (
                self.report_state.vulnerability_reports if self.report_state is not None else []
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

    def collection_snapshot(self, name: str) -> tuple[int | None, list[dict[str, Any]]]:
        """Return a collection cursor and complete bounded projection."""
        if name == "events":
            cursor, events = self.live_view.event_snapshot(limit=MAX_TERMINAL_EVENTS)
            return cursor, [collection_item_projection(event) for event in events]
        return None, self.collection(name)

    def collection_changes(
        self,
        name: str,
        cursor: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return event upserts since a monotonic source cursor."""
        if name != "events":
            raise ValueError(f"Collection {name!r} does not expose incremental changes")
        next_cursor, events = self.live_view.event_changes_since(cursor)
        return next_cursor, [
            collection_item_projection(event) for event in events[-MAX_TERMINAL_EVENTS:]
        ]

    async def handle(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "setup.add_target": self._add_target,
            "setup.remove_target": self._remove_target,
            "setup.clear_targets": self._clear_targets,
            "setup.set_instruction": self._set_instruction,
            "setup.configure": self._configure_setup,
            "setup.start": self._start,
            "setup.confirm_mount": self._confirm_mount,
            "config.update": self._update_config,
            "routes.manage": self._manage_routes,
            "notifications.manage": self._manage_notifications,
            "storage.show": self._show_storage,
            "agent.send_message": self._send_message,
            "agent.stop": self._stop_agent,
            "workspace.find": self._find_workspace,
            "viewer.open": self._open_viewer,
            "app.quit": self._quit,
        }
        handler = handlers.get(command)
        result = (
            await handler(payload) if handler else await self.workspace.handle(command, payload)
        )
        self.notify_changed()
        return result

    async def _manage_routes(self, payload: dict[str, Any]) -> dict[str, Any]:
        operation = str(payload.get("operation") or "list")
        by_name = {r.name.casefold(): r for r in list_saved_routes()}
        by_name.update(route_config.session_routes())
        routes = list(by_name.values())
        if operation == "select":
            name = self._required_string(payload, "name")
            route = next((item for item in routes if item.name.casefold() == name.casefold()), None)
            if route is None:
                raise ValueError(f"Unknown route: {name}")
            self.selected_route = route.name
            set_session_route(route)
        elif operation != "list":
            raise ValueError("routes operation must be list or select")
        return {
            "selected": self.selected_route,
            "routes": [route.public_dict() for route in routes],
        }

    async def _manage_notifications(self, payload: dict[str, Any]) -> dict[str, Any]:
        operation = str(payload.get("operation") or "list")
        if operation == "read":
            notification_id = self._required_string(payload, "id")
            if not self.notification_service.mark_read(notification_id):
                raise ValueError("Notification not found")
        elif operation == "dismiss":
            notification_id = self._required_string(payload, "id")
            if not self.notification_service.dismiss(notification_id):
                raise ValueError("Notification not found")
        elif operation == "clear":
            return {
                "cleared": self.notification_service.clear_read(),
                "unread": self.notification_service.unread_count(),
            }
        elif operation == "action":
            return self._invoke_notification_action(payload)
        elif operation != "list":
            raise ValueError("Unknown notification operation")

        severity = payload.get("severity")
        if severity is not None and severity not in {"info", "warning", "error", "critical"}:
            raise ValueError("Unknown notification severity")
        items = self.notification_service.list(
            unread=True if payload.get("unread") is True else None,
            severity=severity,
            category=str(payload["category"]) if payload.get("category") else None,
            run_id=str(payload["run"]) if payload.get("run") else None,
            agent_id=str(payload["agent"]) if payload.get("agent") else None,
            route_id=str(payload["route"]) if payload.get("route") else None,
            limit=50,
        )
        return {
            "unread": self.notification_service.unread_count(),
            "notifications": [item.to_dict() for item in items],
        }

    def _invoke_notification_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        notification_id = self._required_string(payload, "id")
        action_index = payload.get("index", 0)
        if not isinstance(action_index, int) or isinstance(action_index, bool):
            raise TypeError("action index must be an integer")
        item = self.notification_service.get(notification_id)
        if item is None:
            raise ValueError("Notification not found")
        if action_index < 0 or action_index >= len(item.actions):
            raise ValueError("Notification action not found")
        action = item.actions[action_index]
        self.notification_service.mark_read(item.id)
        # Return a typed UI instruction. The backend never evaluates a shell command.
        return {"action": action.kind, "target": action.target, "label": action.label}

    async def _show_storage(self, _payload: dict[str, Any]) -> dict[str, Any]:
        run_dir = self.report_state.get_run_dir() if self.report_state is not None else None
        state_dir = runtime_state_dir(run_dir) if run_dir is not None else None
        return {
            "run": str(run_dir) if run_dir else "not created yet",
            "database": str(state_dir / "agents.db") if state_dir else "not created yet",
            "transcript": (
                f"{state_dir / 'agents.db'}#transcript_entries" if state_dir else "not created yet"
            ),
            "graph": str(state_dir / "agents.json") if state_dir else "not created yet",
            "log": str(run_dir / "strix.log") if run_dir else "not created yet",
            "global_config": str(Path.home() / ".strix" / "cli-config.json"),
            "global_inbox": str(self.notification_service.path),
        }

    async def _add_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        target = self._required_string(payload, "target")
        if target not in self.targets:
            self.targets.append(target)
        return {"target": target, "total": len(self.targets)}

    async def _remove_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        if payload.get("target_id"):
            target = next(
                (item for item in self.targets if self.target_id(item) == payload["target_id"]),
                "",
            )
            if not target:
                raise ValueError("Target no longer exists; refresh the workspace")
        else:
            target = self._required_string(payload, "target")
        try:
            self.targets.remove(target)
        except ValueError as exc:
            raise ValueError(f"Unknown target: {target}") from exc
        for item in list(self.workspace.attachments):
            if item["path"] == target and item["role"] == "target":
                await self.workspace.handle("attachments.remove", {"id": item["id"]})
        return {"target": target, "total": len(self.targets)}

    async def _clear_targets(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        removed = len(self.targets)
        self.targets.clear()
        for item in list(self.workspace.attachments):
            if item["role"] == "target":
                await self.workspace.handle("attachments.remove", {"id": item["id"]})
        return {"removed": removed, "total": 0}

    @staticmethod
    def target_id(target: str) -> str:
        return hashlib.sha256(target.encode("utf-8")).hexdigest()[:24]

    async def _set_instruction(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        self.instruction = self.prompt_text(payload, "instruction", allow_empty=True)
        return {"instruction": self.instruction}

    async def _configure_setup(  # noqa: PLR0912 - one atomic multi-field command
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Update one or more scan controls while the launch screen is active."""
        self._require_setup_mutable()
        supported = {
            "scan_mode",
            "max_budget_usd",
            "max_turns",
            "max_agents",
            "scope_mode",
            "diff_base",
        }
        unknown = set(payload) - supported
        if unknown:
            raise ValueError(f"Unknown scan setting: {sorted(unknown)[0]}")
        if not payload:
            raise ValueError("No scan setting supplied")

        if "scan_mode" in payload:
            value = payload["scan_mode"]
            if not isinstance(value, str) or value not in SCAN_MODES:
                raise ValueError(f"scan_mode must be one of: {', '.join(SCAN_MODES)}")
            self.scan_mode = value
        if "max_budget_usd" in payload:
            value = payload["max_budget_usd"]
            if value is None:
                self.max_budget_usd = None
            elif (
                not isinstance(value, int | float)
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                or value <= 0
            ):
                raise ValueError("max_budget_usd must be a positive number or null")
            else:
                self.max_budget_usd = float(value)
        if "max_turns" in payload:
            self.max_turns = self._positive_int(payload["max_turns"], "max_turns")
        if "max_agents" in payload:
            value = self._positive_int(payload["max_agents"], "max_agents")
            if value < 2:
                raise ValueError("max_agents must be at least 2")
            self.max_agents = value
        if "scope_mode" in payload:
            value = payload["scope_mode"]
            if not isinstance(value, str) or value not in SCOPE_MODES:
                raise ValueError(f"scope_mode must be one of: {', '.join(SCOPE_MODES)}")
            self.scope_mode = value
        if "diff_base" in payload:
            value = payload["diff_base"]
            if value is not None and not isinstance(value, str):
                raise TypeError("diff_base must be a string or null")
            self.diff_base = value.strip() if isinstance(value, str) and value.strip() else None

        return {
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_turns": self.max_turns,
            "max_agents": self.max_agents,
            "scope_mode": self.scope_mode,
            "diff_base": self.diff_base,
        }

    async def _update_config(  # noqa: PLR0912, PLR0915 - one bounded config schema
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate explicit provider edits; apply them at the next model call."""
        supported = {
            "persist",
            "model",
            "api_key",
            "api_base",
            "reasoning_effort",
            "streaming_enabled",
            "prompt_cache",
            "llm_timeout",
            "max_tool_calls_per_turn",
            "max_context_images",
        }
        unknown = set(payload) - supported
        if unknown:
            raise ValueError(f"Unknown configuration setting: {sorted(unknown)[0]}")
        if not payload:
            raise ValueError("No configuration setting supplied")

        updates: dict[str, Any] = {}
        if "model" in payload:
            updates["STRIX_LLM"] = self._optional_bounded_string(
                payload["model"], "model", maximum=512
            )
        if "api_key" in payload:
            api_key = self._optional_bounded_string(
                payload["api_key"], "api_key", maximum=32 * 1024
            )
            if api_key is not None and ("\r" in api_key or "\n" in api_key):
                raise ValueError("api_key must be a single line")
            updates["LLM_API_KEY"] = api_key
        if "api_base" in payload:
            api_base = self._optional_bounded_string(
                payload["api_base"], "api_base", maximum=2 * 1024
            )
            if api_base is not None:
                parsed = urlparse(api_base)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    raise ValueError("api_base must be an http:// or https:// URL")
                if parsed.username is not None or parsed.password is not None:
                    raise ValueError("api_base must not contain credentials; use /apikey instead")
            updates["LLM_API_BASE"] = api_base
        if "reasoning_effort" in payload:
            value = payload["reasoning_effort"]
            if not isinstance(value, str) or value not in _REASONING_EFFORTS:
                raise ValueError(
                    "reasoning_effort must be one of: " + ", ".join(sorted(_REASONING_EFFORTS))
                )
            updates["STRIX_REASONING_EFFORT"] = value
        for field, alias in (("prompt_cache", "STRIX_PROMPT_CACHE"),):
            if field in payload:
                value = payload[field]
                if not isinstance(value, bool):
                    raise TypeError(f"{field} must be a boolean")
                updates[alias] = value
        if "streaming_enabled" in payload:
            value = payload["streaming_enabled"]
            if not isinstance(value, bool):
                raise TypeError("streaming_enabled must be a boolean")
            updates["LLM_DISABLE_STREAMING"] = not value
        for field, alias, allow_zero in (
            ("llm_timeout", "LLM_TIMEOUT", False),
            ("max_tool_calls_per_turn", "LLM_MAX_TOOL_CALLS_PER_TURN", True),
            ("max_context_images", "STRIX_MAX_CONTEXT_IMAGES", True),
        ):
            if field in payload:
                value = payload[field]
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < (0 if allow_zero else 1)
                ):
                    qualifier = "a non-negative integer" if allow_zero else "a positive integer"
                    raise ValueError(f"{field} must be {qualifier}")
                updates[alias] = value

        route_updates = {
            key: updates.pop(key)
            for key in tuple(updates)
            if key in {"STRIX_LLM", "LLM_API_KEY", "LLM_API_BASE"}
        }
        persist = payload.get("persist") is True
        selected = None
        with contextlib.suppress(ValueError):
            selected = load_routes(
                load_settings(), selected=[self.selected_route] if self.selected_route else None
            )[0]
        edited = selected
        if selected is not None and route_updates:
            edited = RouteConfig.from_dict(selected.to_dict())
            if "STRIX_LLM" in route_updates:
                if not route_updates["STRIX_LLM"]:
                    raise ValueError("A named route model cannot be empty")
                edited.model = str(route_updates["STRIX_LLM"])
                edited.model_id = edited.model.partition("/")[2] or edited.model
            if "LLM_API_BASE" in route_updates:
                edited.base_url = route_updates["LLM_API_BASE"]
            if "LLM_API_KEY" in route_updates:
                from uuid import uuid4

                ref = f"route.{edited.name}.ui-{uuid4().hex[:12]}"
                # A session edit must not overwrite a saved connection's credential.
                get_secret_store().set(ref, str(route_updates["LLM_API_KEY"] or ""))
                edited.api_key_ref = ref
                edited.api_key_env = None
            if persist:
                save_route(edited, replace=True)
            set_session_route(edited)
            self.selected_route = edited.name
        else:
            updates.update(route_updates)
        fields = {f["alias"]: f["id"] for f in settings_fields()}
        for alias, value in updates.items():
            update_setting(fields[alias], value, persist=persist)
        settings = load_settings()
        return {
            "saved": persist,
            "model": edited.model
            if edited is not None and route_updates
            else settings.llm.model or "",
            "api_key_configured": bool(
                route_updates.get("LLM_API_KEY")
                or (selected and selected.api_key_ref)
                or settings.llm.api_key
            ),
            "api_base": _display_api_base(edited.base_url or "")
            if edited is not None and route_updates
            else _display_api_base(settings.llm.api_base or ""),
            "reasoning_effort": settings.llm.reasoning_effort,
            "selected_route": self.selected_route,
        }

    async def _start(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.scan_started or self._start_in_progress:
            raise RuntimeError("Scan is already starting or running")
        # Launching with no target mounts the working directory, so it requires
        # the user's explicit confirmation rather than happening silently.
        mount_working_dir = payload.get("mount_working_dir", False)
        if not isinstance(mount_working_dir, bool):
            raise TypeError("mount_working_dir must be a boolean")
        try:
            routes = load_routes(
                load_settings(),
                selected=[self.selected_route] if self.selected_route else None,
            )
        except ValueError as exc:
            raise ValueError("No model configured. Use /model provider/model in the TUI.") from exc
        if not routes:
            raise ValueError("No model configured. Use /model provider/model in the TUI.")
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        if not self.targets and not mount_working_dir:
            raise ValueError("No target set. Add a target first.")
        # The model check runs while still on the start screen, for a bare
        # prompt as much as for a named target, so a failure lands in the setup
        # log where the user can fix it and retry rather than in a dead run.
        await self._verify_model()
        if not self.targets:
            # Mounting the working directory needs the user's confirmation, and
            # that is asked in the live view. Enter it now and prepare nothing
            # until the answer arrives, so declining leaves no run behind.
            self.pending_workspace_mount = str(Path.cwd())
            self.setup_mode = False
            self.scan_started = True
            self.scan_state = "preparing"
            return {"started": True}
        await self._begin_scan()
        return {"started": True}

    async def _verify_model(self) -> None:
        if self._on_verify is None:
            return
        self._start_in_progress = True
        try:
            await self._on_verify()
        finally:
            self._start_in_progress = False

    async def _begin_scan(self) -> None:
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        self._start_in_progress = True
        try:
            await self._on_start()
        except Exception as exc:
            if not self.setup_mode:
                # The live view is already up, so the failure has to show there.
                self.fail_preparation(str(exc))
            raise
        finally:
            self._start_in_progress = False
        self.setup_mode = False
        self.scan_started = True
        self.scan_state = "running"

    async def _confirm_mount(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Answer the pending working-directory mount asked for in the live view."""
        mount = self.pending_workspace_mount
        if mount is None:
            raise RuntimeError("No mount confirmation is pending")
        approved = payload.get("approved")
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        self.pending_workspace_mount = None
        # Declining skips the mount, it does not abandon the scan. The prompt is
        # the whole of the input either way; the working directory is only an
        # extra the agent may look at, so the run goes ahead without one.
        self.workspace_mount = mount if approved else None
        await self._begin_scan()
        return {"approved": approved}

    async def _send_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        message = self.prompt_text(payload, "message")
        if self.coordinator is None:
            raise RuntimeError("Agent coordinator is unavailable")
        if self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        message += self.workspace.attachment_context()
        if self.scan_loop is asyncio.get_running_loop():
            delivered = await self.coordinator.send(
                agent_id,
                {"from": "user", "content": message, "type": "instruction"},
            )
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.send(
                    agent_id,
                    {"from": "user", "content": message, "type": "instruction"},
                ),
                self.scan_loop,
            )
            delivered = await asyncio.wrap_future(future)
        if not delivered:
            raise RuntimeError("Message could not be delivered")
        self.live_view.record_user_message(agent_id, message)
        self.workspace.pending_attachment_ids.clear()
        self.live_view.upsert_agent(agent_id, status="waiting", error_message=None)
        return {"sent": True}

    async def _stop_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        agent = self.live_view.agents.get(agent_id)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_id}")
        status = str(agent.get("status", ""))
        if status not in _STOPPABLE_AGENT_STATUSES:
            raise RuntimeError(f"Agent '{agent_id}' cannot be stopped while {status or 'unknown'}")
        if self.coordinator is None or self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        if self.scan_loop is asyncio.get_running_loop():
            accepted = await self.coordinator.cancel_descendants_graceful(agent_id)
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.cancel_descendants_graceful(agent_id), self.scan_loop
            )
            accepted = await asyncio.wrap_future(future)
        if not accepted:
            raise RuntimeError(f"Agent '{agent_id}' is no longer active")
        return {"stopped": True}

    def _workspace_roots(self) -> list[Path]:
        """Return existing local roots in user-facing priority order."""
        candidates: list[Any] = []
        if self.workspace_mount:
            candidates.append(self.workspace_mount)
        candidates.extend(
            source.get("source_path")
            for source in getattr(self.args, "local_sources", None) or []
            if isinstance(source, dict)
        )
        for target in getattr(self.args, "targets_info", None) or []:
            if not isinstance(target, dict):
                continue
            details = target.get("details")
            if isinstance(details, dict):
                candidates.extend((details.get("cloned_repo_path"), details.get("target_path")))
        # Targets entered on the setup screen have not gone through
        # ``prepare_run`` yet, but a local path can still be searched directly.
        candidates.extend(self.targets)

        roots: list[Path] = []
        seen: set[Path] = set()
        for candidate in candidates:
            if not isinstance(candidate, str | Path) or not str(candidate).strip():
                continue
            try:
                path = Path(candidate).expanduser().resolve()
            except (OSError, RuntimeError):
                continue
            if not path.is_dir() or path in seen:
                continue
            seen.add(path)
            roots.append(path)
        if roots:
            return roots
        current = Path.cwd().resolve()
        return [current] if current.is_dir() else []

    async def _find_workspace(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Run a literal workspace lookup without consuming an agent turn."""
        query = self._required_string(payload, "query")
        roots = self._workspace_roots()
        if not roots:
            raise RuntimeError("No local workspace is available to search")

        limit = 50
        matches: list[dict[str, Any]] = []
        total = 0
        truncated = False
        searched: list[str] = []
        multiple_roots = len(roots) > 1
        for root in roots:
            remaining = max(1, limit - len(matches))
            result = await asyncio.to_thread(
                search_local_workspace,
                root,
                query,
                max_results=remaining,
            )
            searched.append(str(root))
            total += int(result.get("match_count", 0) or 0)
            truncated = truncated or bool(result.get("truncated"))
            for match in result.get("matches", []):
                if not isinstance(match, dict) or len(matches) >= limit:
                    continue
                projected = dict(match)
                if multiple_roots:
                    projected["path"] = f"{root.name}/{projected.get('path', '')}"
                matches.append(projected)
            if len(matches) >= limit:
                truncated = True
                break

        return {
            "query": query,
            "root": searched[0] if len(searched) == 1 else f"{len(searched)} local roots",
            "match_count": total,
            "returned_count": len(matches),
            "truncated": truncated or total > len(matches),
            "matches": matches,
        }

    async def _open_viewer(self, _payload: dict[str, Any]) -> dict[str, Any]:
        from strix.core.paths import runs_base_dir
        from strix.interface.viewer.workspace import BrowserWorkspace

        if self.viewer_url:
            with contextlib.suppress(Exception):
                from strix.interface.viewer.server import fresh_authorized_url

                webbrowser.open(
                    fresh_authorized_url(self._viewer_httpd, self.viewer_url)
                    if self._viewer_httpd is not None
                    else self.viewer_url
                )
            return {"status": "running", "url": self.viewer_url}
        try:
            from strix.interface.tui.backend.messages import (
                send_user_message_to_agent,
            )
            from strix.interface.viewer.server import (
                bundle_is_built,
                serve,
            )

            if not bundle_is_built():
                self.viewer_status = "unavailable"
                return {"status": self.viewer_status, "error": "Viewer UI not built"}

            def steer(agent_id: str, message: str) -> bool:
                return send_user_message_to_agent(
                    coordinator=self.coordinator,
                    loop=self.scan_loop,
                    live_view=self.live_view,
                    target_agent_id=agent_id,
                    message=message,
                    notify_changed=self.notify_changed,
                    wait_for_delivery=True,
                )

            self._viewer_bridge = BrowserWorkspace(self, asyncio.get_running_loop())
            httpd, url, _bootstrap_nonce = serve(
                self.report_state.get_run_dir()
                if self.report_state
                else runs_base_dir() / "workspace",
                open_browser=True,
                steer_handler=steer,
                workspace=self._viewer_bridge,
            )
            self._viewer_httpd = httpd
            self.viewer_url = url
            self.viewer_status = "running"
        except Exception:  # noqa: BLE001 - viewer startup failures must not crash the TUI
            self.viewer_status = "failed"
            return {"status": self.viewer_status, "error": "Viewer failed to start"}
        else:
            return {"status": self.viewer_status, "url": self.viewer_url}

    def close_viewer(self) -> None:
        httpd = self._viewer_httpd
        if httpd is None:
            return
        bridge = getattr(self, "_viewer_bridge", None)
        if bridge is not None:
            bridge.closed = True
        self._viewer_httpd = None
        with contextlib.suppress(Exception):
            httpd.shutdown()
            httpd.server_close()

    def close(self) -> None:
        """Release process-local subscriptions and viewer resources."""
        self.close_viewer()
        unsubscribe = self._unsubscribe_notifications
        self._unsubscribe_notifications = lambda: None
        unsubscribe()

    async def _quit(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self.close_viewer()
        if self._on_quit is not None:
            await self._on_quit()
        self.scan_state = "stopped"
        return {"quitting": True}

    @staticmethod
    def _required_string(payload: dict[str, Any], name: str) -> str:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _positive_int(value: Any, name: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return value

    @staticmethod
    def prompt_text(payload: dict[str, Any], name: str, *, allow_empty: bool = False) -> str:
        value = payload.get(name, "" if allow_empty else None)
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        if not value.strip():
            if allow_empty:
                return ""
            raise ValueError(f"{name} must be a non-empty string")
        if len(value.encode("utf-8")) > _MAX_PROMPT_BYTES:
            raise ValueError(f"{name} is too large (maximum 256 KiB)")
        return value

    @staticmethod
    def _optional_bounded_string(value: Any, name: str, *, maximum: int) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string or null")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{name} must be non-empty or null")
        if len(cleaned) > maximum:
            raise ValueError(f"{name} is too long")
        return cleaned

    def _require_setup_mutable(self) -> None:
        if not self.setup_mode or self.scan_started or self._start_in_progress:
            raise RuntimeError("Setup can no longer be changed after the scan starts")


def _display_api_base(value: str) -> str:
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


# Compatibility name for existing transports and integrations.
TuiController = ApplicationController
