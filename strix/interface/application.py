"""UI-independent state and command controller for interactive Strix clients."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import math
import webbrowser
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.application.commands import Command, CommandRegistry
from strix.bootstrap import create_app_services
from strix.config.settings import DEFAULT_MAX_AGENTS, DEFAULT_MAX_TURNS
from strix.core.paths import runs_base_dir
from strix.interface.projectors import WorkspaceProjector
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.backend.projection import SCAN_MODES, SCOPE_MODES, sanitize_terminal_text
from strix.interface.viewer.server import bundle_is_built, fresh_authorized_url, serve
from strix.interface.viewer.workspace import BrowserWorkspace
from strix.interface.workspace import WorkspaceCommands
from strix.tools.workspace_search import search_local_workspace


if TYPE_CHECKING:
    from strix.application.context import AppServices, ScanContext
    from strix.domain.app_state import LaunchState
    from strix.notifications import Notification
    from strix.report.state import ReportState


_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})
_MAX_PROMPT_BYTES = 256 * 1024
ChangeCallback = Callable[[], None]
StartCallback = Callable[[], Awaitable[None]]
VerifyCallback = Callable[[], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]


class ApplicationController:
    """Own setup state and expose serializable scan state to any TUI."""

    def __init__(
        self,
        args: LaunchState,
        *,
        live_view: TuiLiveView | None = None,
        coordinator: Any = None,
        report_state: ReportState | None = None,
        services: AppServices | None = None,
        on_start: StartCallback | None = None,
        on_verify: VerifyCallback | None = None,
        on_quit: QuitCallback | None = None,
        on_change: ChangeCallback | None = None,
    ) -> None:
        self.args = args
        self.services = services or create_app_services()
        self.workspace = WorkspaceCommands(self)
        self.commands = CommandRegistry()
        self.projector = WorkspaceProjector()
        self.live_view = live_view or TuiLiveView()
        self.coordinator = coordinator
        self.report_state = report_state
        self.scan_context: ScanContext | None = None
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
        # Display-only projection of the last automatic router decision.
        self.selected_route = ""
        self.recovery: dict[str, Any] = {}
        self.notification_service = self.services.notifications
        self._unsubscribe_notifications = self.notification_service.subscribe(self._on_notification)
        self._register_commands()

    def _register_commands(self) -> None:
        handlers = {
            "setup.add_target": self._add_target,
            "setup.remove_target": self._remove_target,
            "setup.clear_targets": self._clear_targets,
            "setup.set_instruction": self._set_instruction,
            "setup.configure": self._configure_setup,
            "setup.start": self._start,
            "setup.confirm_mount": self._confirm_mount,
            "notifications.manage": self._manage_notifications,
            "agent.send_message": self._send_message,
            "agent.stop": self._stop_agent,
            "workspace.find": self._find_workspace,
            "viewer.open": self._open_viewer,
            "app.quit": self._quit,
        }
        for name, handler in handlers.items():
            self.commands.register(name, handler)
        for namespace in (
            "attachments",
            "mcp",
            "notifications",
            "paths",
            "providers",
            "models",
            "router",
            "update",
            "doctor",
            "scan",
            "sessions",
            "settings",
        ):
            self.commands.register_namespace(namespace, self._handle_workspace_command)

    async def _handle_workspace_command(self, command: Command) -> dict[str, Any]:
        return await self.workspace.handle(command.name, command.payload)

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
        if notification.event_type == "model.progress":
            self.recovery = {}
        elif notification.event_type.startswith(
            ("model.", "runtime.route.", "security.credential", "agent.failed")
        ) and not notification.event_type.endswith("recovered"):
            self.recovery = {
                "state": notification.event_type,
                "title": notification.title,
                "detail": notification.detail,
                "agent_id": notification.agent_id,
            }
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
        scan_context: ScanContext | None = None,
    ) -> None:
        if report_state is not None:
            self.report_state = report_state
        if scan_loop is not None:
            self.scan_loop = scan_loop
        if scan_context is not None:
            self.scan_context = scan_context

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
        return self.projector.snapshot(self)

    def collection(self, name: str) -> list[dict[str, Any]]:
        return self.projector.collection(self, name)

    def collection_snapshot(self, name: str) -> tuple[int | None, list[dict[str, Any]]]:
        return self.projector.collection_snapshot(self, name)

    def collection_changes(
        self,
        name: str,
        cursor: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        return self.projector.collection_changes(self, name, cursor)

    async def handle(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        result = await self.commands.dispatch(Command(command, dict(payload)))
        self.notify_changed()
        return result

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

    async def _start(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.scan_started or self._start_in_progress:
            raise RuntimeError("Scan is already starting or running")
        # Launching with no target mounts the working directory, so it requires
        # the user's explicit confirmation rather than happening silently.
        mount_working_dir = payload.get("mount_working_dir", False)
        if not isinstance(mount_working_dir, bool):
            raise TypeError("mount_working_dir must be a boolean")
        try:
            from strix.config.runtime_routes import load_app_routes  # noqa: PLC0415

            routes = load_app_routes()
        except ValueError as exc:
            raise ValueError(
                "No eligible model is configured. Use /connect, then /models."
            ) from exc
        if not routes:
            raise ValueError("No eligible model is configured. Use /connect, then /models.")
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
        if self.viewer_url:
            with contextlib.suppress(Exception):
                webbrowser.open(
                    fresh_authorized_url(self._viewer_httpd, self.viewer_url)
                    if self._viewer_httpd is not None
                    else self.viewer_url
                )
            return {"status": "running", "url": self.viewer_url}
        try:
            if not bundle_is_built():
                self.viewer_status = "unavailable"
                return {"status": self.viewer_status, "error": "Viewer UI not built"}

            self._viewer_bridge = BrowserWorkspace(self, asyncio.get_running_loop())
            httpd, url, _bootstrap_nonce = serve(
                self.report_state.get_run_dir()
                if self.report_state
                else runs_base_dir() / "workspace",
                open_browser=True,
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
