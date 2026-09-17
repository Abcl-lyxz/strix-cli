"""Shared local scan lifecycle, with a terminal transport subclass."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import shutil
import sys
import time
from copy import deepcopy
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from strix.bootstrap import create_scan_context
from strix.config import load_settings
from strix.config.app_config import get_config_service
from strix.config.runtime_routes import load_app_routes
from strix.config.settings import DEFAULT_MAX_AGENTS
from strix.core.agents import AgentCoordinator
from strix.core.hooks import BudgetExceededError
from strix.core.ownership import RunLease, run_is_active
from strix.core.paths import run_dir_for, runs_base_dir, runtime_state_dir
from strix.core.runner import run_strix_scan
from strix.interface.application import ApplicationController
from strix.interface.output import WorkspaceOutput
from strix.interface.scan_setup import (
    build_targets_info,
    preflight_model_connection,
    prepare_run,
)
from strix.interface.targets import read_workspace_files
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.backend.server import TuiBackendServer
from strix.interface.tui.sidecar import (
    check_return_code,
    child_environment,
    launch_tui_process,
    package_version,
    terminate_process,
    tui_executable,
    tui_source_dir,
    wait_process,
)
from strix.llm.errors import classify_model_failure
from strix.report.state import ReportState
from strix.routing import resolve_route_secrets
from strix.telemetry import report_error, set_scan_phase
from strix.utils.resource_paths import get_strix_resource_path


if TYPE_CHECKING:
    import socket
    import subprocess

    from strix.application.context import ScanContext
    from strix.domain.app_state import LaunchState, RunConfig

logger = logging.getLogger(__name__)

_COMPILE_NOTICE = "Compiling the TUI from source (cached after the first run)..."
_TRANSIENT_PREFLIGHT_RETRY_DELAY = 10.0
_QUALITY_RANK = {"frontier": 0, "strong": 1, "standard": 2, "economy": 3, "unknown": 4}


def _route_quality_key(route: Any) -> tuple[int, str]:
    return _QUALITY_RANK.get(route.quality_tier, _QUALITY_RANK["unknown"]), route.name


def _print_compile_notice(stream: Any) -> None:
    """Print startup status without assuming the parent supports ANSI escapes."""
    print(_COMPILE_NOTICE, file=stream, flush=True)


def _revision_count(report: dict[str, Any]) -> int:
    history = report.get("update_history")
    return len(history) if isinstance(history, list) else 0


class GoTuiPreActivationError(RuntimeError):
    """A sidecar failure raised before the Go TUI activates."""


class WorkspaceRuntime:
    def __init__(self, args: LaunchState) -> None:
        self.args = args
        self.live_view = TuiLiveView()
        self.coordinator = AgentCoordinator(
            max_active_agents=getattr(args, "max_agents", DEFAULT_MAX_AGENTS)
        )
        self.report_state: ReportState | None = None
        self.scan_context: ScanContext | None = None
        self.scan_config: dict[str, Any] = {}
        self.run_config_snapshot: RunConfig | None = None
        self.scan_task: asyncio.Task[None] | None = None
        self.run_lease: RunLease | None = None
        self.scan_error: BaseException | None = None
        self._last_sync_fingerprint = ""
        self._error_noted_agents: set[str] = set()
        self.model_verified = False
        self.verified_connection: tuple[str, str, str] | None = None
        self._setup_preflight: asyncio.Task[None] | None = None
        self._preflight_failure: str | None = None
        self._preflight_failure_connection: tuple[str, str, str] | None = None
        self._preflight_retry_at = 0.0
        self.controller = ApplicationController(
            args,
            live_view=self.live_view,
            coordinator=self.coordinator,
            on_start=self.start_from_setup,
            on_verify=self.ensure_model_verified,
            on_quit=self.quit,
        )
        self.coordinator.set_notification_publisher(self.controller.services.notifications)
        self.controller.workspace.runtime = self

    async def new_session(self, resume: str = "") -> None:  # noqa: PLR0915 - reset all scan-owned state
        record: dict[str, Any] = {}
        if self.scan_task is not None and not self.scan_task.done():
            raise RuntimeError("Stop the active scan before starting or resuming another")
        if resume:
            root = runs_base_dir().resolve()
            run = (root / resume).resolve()
            if run.parent != root or not (run / "run.json").is_file():
                raise ValueError("Unknown local run")
            if run_is_active(run):
                raise RuntimeError("This run is already owned by a running process")
            record = json.loads((run / "run.json").read_text(encoding="utf-8"))
            if record.get("schema_version") != 2:
                raise RuntimeError("Legacy runs are read-only in Strix v2 and cannot be resumed")
        self.scan_task = None
        self.scan_error = None
        self.run_config_snapshot = None
        self.model_verified = False
        self.verified_connection = None
        self._preflight_failure = None
        self._preflight_failure_connection = None
        self._preflight_retry_at = 0.0
        self.coordinator = AgentCoordinator(max_active_agents=self.controller.max_agents)
        self.coordinator.set_notification_publisher(self.controller.services.notifications)
        self.live_view = TuiLiveView()
        self.controller.coordinator = self.coordinator
        self.controller.live_view = self.live_view
        self.controller.report_state = None
        self.controller.scan_context = None
        self.controller.scan_started = False
        self.controller.setup_mode = True
        self.controller.scan_state = "setup"
        self.controller.error = None
        self.controller.recovery = {}
        self.controller.workspace_mount = None
        self.controller.pending_workspace_mount = None
        self._last_sync_fingerprint = ""
        self._error_noted_agents.clear()
        self.controller.targets = []
        self.controller.instruction = ""
        self.controller.messages.clear()
        self.controller.workspace.attachments.clear()
        self.controller.workspace.pending_attachment_ids.clear()
        self.args.workspace_files = []
        self.args.targets_info = []
        self.args.target = []
        self.args.target_list = []
        self.args.instruction = None
        self.args.resume = None
        self.args.run_name = None
        self.args.workspace_mount = None
        self.args.workspace_subdir = None
        self.args.local_sources = []
        self.args.diff_scope = {"active": False}
        self.report_state = None
        self.scan_context = None
        if resume:
            self.args.resume = resume
            self.args.run_name = resume
            self.args.targets_info = record.get("targets_info", [])
            self.args.local_sources = record.get("local_sources", [])
            self.args.workspace_files = record.get("workspace_files", [])
            self.args.diff_scope = record.get("diff_scope", {"active": False})
            self.args.workspace_mount = record.get("workspace_mount")
            self.controller.workspace_mount = self.args.workspace_mount
            for field in ("scan_mode", "scope_mode", "diff_base"):
                if field in record:
                    setattr(self.args, field, record[field])
                    setattr(self.controller, field, record[field])
            self.controller.targets = [
                t["original"] for t in self.args.targets_info if t.get("original")
            ]
            self.controller.instruction = record.get("instruction", "")
        self.controller.notify_changed()

    def init_run_state(self) -> None:
        frozen = self.run_config_snapshot or self.args.draft.freeze()
        if self.args.run_name is None:
            raise RuntimeError("cannot initialize a run before it has a name")
        lease = RunLease(run_dir_for(self.args.run_name))
        lease.acquire()
        self.run_lease = lease
        self.scan_config = {
            "schema_version": 2,
            "scan_id": self.args.run_name,
            "targets": list(frozen.targets_info),
            "user_instructions": frozen.instruction or "",
            "run_name": self.args.run_name,
            "diff_scope": self.args.diff_scope,
            "scan_mode": frozen.scan_mode,
            "non_interactive": False,
            "local_sources": self.args.local_sources or [],
            "workspace_files": list(frozen.workspace_files),
            "scope_mode": frozen.scope_mode,
            "diff_base": frozen.diff_base,
            "resume_instruction": self.args.user_explicit_instruction or "",
            "max_agents": frozen.max_agents,
            "workspace_mount": getattr(self.args, "workspace_mount", None) or "",
            "sandbox_profile": frozen.sandbox_profile,
            "tool_pack": frozen.tool_pack,
            "scope_cidr": getattr(self.args, "scope_cidr", None),
            "network_interface": getattr(self.args, "network_interface", None),
            "packet_rate_limit": getattr(self.args, "packet_rate_limit", None),
            "workspace_mode": frozen.workspace_mode,
            "workspace_subdir": getattr(self.args, "workspace_subdir", None) or "",
        }
        self.report_state = ReportState(self.scan_config["run_name"])
        self.report_state.hydrate_from_run_dir()
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        self.scan_context = create_scan_context(
            scan_id=self.scan_config["run_name"],
            run_dir=self.report_state.get_run_dir(),
            state_dir=runtime_state_dir(self.report_state.get_run_dir()),
            report_state=self.report_state,
            services=self.controller.services,
        )
        self.live_view.hydrate_from_run_dir(self.report_state.get_run_dir())
        self.controller.set_runtime(
            report_state=self.report_state,
            scan_loop=asyncio.get_running_loop(),
            scan_context=self.scan_context,
        )
        self.report_state.vulnerability_found_callback = lambda _report: (
            self.controller.notify_changed()
        )
        self.report_state.vulnerability_updated_callback = lambda _report: (
            self.controller.notify_changed()
        )
        self.controller.notify_changed()

    async def check_setup_model(self) -> None:
        """Verify the model route as soon as the start screen is up.

        The same round trip a direct launch makes in prepare_and_start, run in
        the background so the screen paints first and the outcome lands in the
        setup log before the user has finished typing.
        """
        try:
            self._configured_model()
        except ValueError:
            return
        try:
            await self._preflight_model()
        except Exception as exc:  # noqa: BLE001 - provider SDKs raise heterogeneous errors
            self._remember_preflight_failure(exc)
            logger.warning("Go TUI setup model preflight failed: %s", exc)
            self.controller.add_message(
                f"Model connection failed: {self._preflight_failure}", "error"
            )
            return
        self.controller.add_message("Model connection verified")

    async def ensure_model_verified(self) -> None:
        """Hold a setup launch until the model has answered once."""
        preflight = self._setup_preflight
        if preflight is not None and not preflight.done():
            await asyncio.shield(preflight)
        current_connection = self._connection_signature()
        if self.model_verified and self.verified_connection == current_connection:
            return
        if (
            self._preflight_failure
            and self._preflight_failure_connection == current_connection
            and time.monotonic() < self._preflight_retry_at
        ):
            raise RuntimeError(self._preflight_failure)
        try:
            await self._preflight_model()
        except Exception as exc:
            self._remember_preflight_failure(exc)
            logger.warning("Go TUI setup model preflight failed: %s", exc)
            report_error("model_connection_failed", exc)
            raise RuntimeError(f"Model connection failed: {self._preflight_failure}") from exc

    async def _preflight_model(self) -> None:
        model = self._configured_model()
        self.controller.add_message("Verifying model connection...")
        set_scan_phase("preflight")
        route = None
        with contextlib.suppress(ValueError):
            route = next(
                (candidate for candidate in load_app_routes() if candidate.model == model),
                None,
            )
        needs_capability_probe = route is not None and (
            route.supports_tools is not True
            or route.context_window_tokens is None
            or route.metadata_confidence not in {"verified", "catalog"}
        )
        probe_routes = [route] if route is not None and needs_capability_probe else None
        verification = await preflight_model_connection(
            model,
            check_tools=needs_capability_probe,
            routes_override=probe_routes,
            allow_unverified=needs_capability_probe,
        )
        if needs_capability_probe and route is not None and verification is not None:
            service = get_config_service()
            descriptor = service.load().models.get(route.name)
            if descriptor is not None:
                service.upsert_models(
                    [
                        descriptor.model_copy(
                            update={
                                "supports_tools": verification.supports_tools,
                                "supports_vision": (
                                    verification.supports_vision
                                    if verification.supports_vision is not None
                                    else descriptor.supports_vision
                                ),
                                "context_window_tokens": (
                                    verification.context_window_tokens
                                    or descriptor.context_window_tokens
                                ),
                                "max_output_tokens": (
                                    verification.max_output_tokens or descriptor.max_output_tokens
                                ),
                                "metadata_source": verification.source,
                                "metadata_confidence": "verified",
                                "verified_at": datetime.now(UTC).isoformat(),
                            }
                        )
                    ]
                )
        self.model_verified = True
        self.verified_connection = self._connection_signature()
        self._preflight_failure = None
        self._preflight_failure_connection = None
        self._preflight_retry_at = 0.0

    def _remember_preflight_failure(self, exc: BaseException) -> None:
        """Cache permanent setup failures and briefly debounce transient ones."""
        self.model_verified = False
        self.verified_connection = None
        self._preflight_failure = str(exc) or type(exc).__name__
        self._preflight_failure_connection = self._connection_signature()
        kind = classify_model_failure(exc)
        self._preflight_retry_at = (
            float("inf")
            if kind in {"authentication", "billing", "incompatible", "policy"}
            else time.monotonic() + _TRANSIENT_PREFLIGHT_RETRY_DELAY
        )

    def _connection_signature(self) -> tuple[str, str, str]:
        routes = load_app_routes()
        route = min(routes, key=_route_quality_key)
        key, headers = resolve_route_secrets(route)
        secrets = (key, headers)
        digest = hashlib.sha256(
            json.dumps(secrets, sort_keys=True, default=str).encode()
        ).hexdigest()
        return route.model, digest, route.base_url or ""

    def _configured_model(self) -> str:
        routes = load_app_routes()
        if not routes:
            raise ValueError("No eligible model configured. Use /connect, then /models.")
        return min(routes, key=_route_quality_key).model

    def _start_preparation(self) -> asyncio.Task[None]:
        """Kick off the work that runs behind the freshly painted TUI."""
        if self.controller.setup_mode:
            self._setup_preflight = asyncio.create_task(self.check_setup_model())
            return self._setup_preflight
        self.controller.begin_preparation()
        return asyncio.create_task(self.prepare_and_start())

    async def start_from_setup(self) -> None:
        candidate = deepcopy(self.args)
        candidate.scan_mode = self.controller.scan_mode
        candidate.instruction = self.controller.instruction
        # Held apart from instruction, which prepare_run prefixes with the
        # diff-scope preamble, so the transcript can show what was typed.
        candidate.user_instruction = self.controller.instruction or None
        candidate.max_budget_usd = self.controller.max_budget_usd
        candidate.max_turns = self.controller.max_turns
        candidate.max_agents = self.controller.max_agents
        candidate.scope_mode = self.controller.scope_mode
        candidate.diff_base = self.controller.diff_base
        existing_targets = [
            str(target["original"])
            for target in candidate.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        targets_changed = self.controller.targets != existing_targets
        # A confirmed target-less launch mounts the working directory for the
        # agent to work in, without making it a scan target.
        candidate.workspace_mount = self.controller.workspace_mount
        if targets_changed:
            # Rebuild the full typed set so path canonicalization and local
            # deduplication match the CLI.
            candidate.target = list(self.controller.targets)
            candidate.target_list = []
            build_targets_info(candidate)
        try:
            prepare_run(candidate)
        except Exception as exc:
            report_error("scan_preparation_failed", exc)
            raise

        self.args = candidate
        self.controller.args = candidate
        self.run_config_snapshot = candidate.draft.freeze()
        self.init_run_state()
        self.start_scan()

    async def prepare_and_start(self) -> None:
        """Prepare a directly-launched scan once the TUI is on screen.

        The model round trip and run preparation run here rather than before
        launch so the interface appears immediately.
        """
        model = self._configured_model()
        set_scan_phase("preflight")
        try:
            await preflight_model_connection(
                model,
            )
        except Exception as exc:
            logger.exception("Go TUI scan preparation failed")
            report_error("model_connection_failed", exc)
            self.controller.fail_preparation(str(exc))
            return
        try:
            prepare_run(self.args)
        except Exception as exc:
            logger.exception("Go TUI scan preparation failed")
            report_error("scan_preparation_failed", exc)
            self.controller.fail_preparation(str(exc))
            return
        self.run_config_snapshot = self.args.draft.freeze()
        self.controller.scan_state = "running"
        self.init_run_state()
        self.start_scan()

    def start_scan(self) -> None:
        if self.scan_task is None:
            self.scan_task = asyncio.create_task(self._run_scan())

    async def _run_scan(self) -> None:
        frozen = self.run_config_snapshot or self.args.draft.freeze()
        image = str(load_settings().runtime.image or "strix-sandbox:latest")
        try:
            await run_strix_scan(
                scan_config=self.scan_config,
                scan_id=self.scan_config["run_name"],
                run_lease=self.run_lease,
                image=image,
                local_sources=self.args.local_sources or [],
                extra_files=read_workspace_files(getattr(self.args, "workspace_files", None)),
                coordinator=self.coordinator,
                interactive=True,
                max_turns=frozen.max_turns,
                max_agents=frozen.max_agents,
                max_budget_usd=frozen.max_budget_usd,
                event_sink=self.capture_event,
                mcp_status_sink=self.capture_mcp_status,
                scan_context=self.scan_context,
            )
            await self._sync_agent_state()
            if self.controller.scan_state == "running":
                self.controller.scan_state = "stopped"
        except (asyncio.CancelledError, BudgetExceededError):
            report_status = (
                self.report_state.run_record.get("status")
                if self.report_state is not None
                else None
            )
            self.controller.scan_state = "completed" if report_status == "completed" else "stopped"
        except Exception as exc:
            logger.exception("Go TUI scan failed")
            report_error("unhandled_exception", exc)
            if self.report_state is not None and self.report_state.scan_ended_exit_reason is None:
                self.report_state.scan_ended_exit_reason = "error"
            self.scan_error = exc
            self.controller.error = str(exc)
            self.controller.scan_state = "failed"
        finally:
            if self.run_lease is not None:
                self.run_lease.close()
                self.run_lease = None
            with contextlib.suppress(Exception):
                await self._sync_agent_state()
            self.controller.notify_changed()

    def capture_event(self, agent_id: str, event: Any) -> None:
        data = getattr(event, "data", None)
        if getattr(data, "type", "") == "response.completed":
            self.controller.recovery = {}
        self.live_view.ingest_sdk_event(agent_id, event)
        self.controller.notify_changed()

    def capture_mcp_status(self, roster: list[dict[str, Any]]) -> None:
        """Receive the engine's MCP connection roster and hand it to the controller.

        Runs on the scan's event loop (called from the runner at establishment
        and from a session's on-dead callback), the same loop that drives
        ``capture_event``, so updating the controller and repainting here is
        safe. The controller renders it as the sidebar MCP connections panel."""
        self.controller.set_mcp_connections(roster)

    async def _sync_agent_state(  # noqa: PLR0912,PLR0915 - explicit lifecycle transitions
        self,
    ) -> bool:
        parent_of, statuses, names, errors = await self.coordinator.graph_snapshot()
        changed = False
        for agent_id, status in statuses.items():
            error = errors.get(agent_id)
            wait_kind = self.coordinator.wait_kinds.get(agent_id, "")
            display_status = str(status)
            operation = self.coordinator.metadata.get(agent_id, {}).get("operation")
            if status == "running" and operation in {"queued", "retrying", "compacting"}:
                display_status = str(operation)
            if status == "waiting":
                display_status = {
                    "provider": "waiting_provider",
                    "blocked": "blocked",
                    "user": "waiting_user",
                    "agents": "waiting_agents",
                    "stalled": "blocked",
                }.get(wait_kind, "queued")
            changed = (
                self.live_view.upsert_agent(
                    agent_id,
                    name=names.get(agent_id, agent_id),
                    parent_id=parent_of.get(agent_id),
                    status=display_status,
                    error_message=error,
                )
                or changed
            )
            public_metadata = self.coordinator.metadata.get(agent_id, {})
            public_agent = self.live_view.agents[agent_id]
            for key in ("operation", "compaction_count", "last_progress_at"):
                value = public_metadata.get(key)
                if value is not None and public_agent.get(key) != value:
                    public_agent[key] = value
                    changed = True
            if self.live_view.agents[agent_id].get("wait_kind", "") != wait_kind:
                self.live_view.agents[agent_id]["wait_kind"] = wait_kind
                changed = True
            if status in {"failed", "crashed"} and error:
                if agent_id not in self._error_noted_agents:
                    self._error_noted_agents.add(agent_id)
                    self.live_view.record_agent_error(agent_id, error)
                    changed = True
            else:
                self._error_noted_agents.discard(agent_id)

        # The user's opening message waits for the root agent to exist, which is
        # the first thing this sync learns about.
        changed = self.live_view.flush_user_instruction() or changed

        roots = [agent_id for agent_id, parent_id in parent_of.items() if parent_id is None]
        root_id = roots[0] if roots else None
        root_status = statuses.get(root_id) if root_id is not None else None
        root_wait_kind = self.coordinator.wait_kinds.get(root_id, "") if root_id else ""
        report_status = (
            self.report_state.run_record.get("status") if self.report_state is not None else None
        )
        scan_state = self.controller.scan_state
        if root_status in {"failed", "crashed"}:
            scan_state = "failed"
            if root_id is not None and errors.get(root_id):
                self.controller.error = errors[root_id]
        elif scan_state == "failed" and root_status in {"running", "waiting", "budget_paused"}:
            scan_state = "running"
            self.controller.error = None
        elif scan_state == "stopped":
            pass
        elif scan_state != "failed":
            if report_status == "completed":
                scan_state = "completed"
            elif root_status == "stopped":
                scan_state = "stopped"
            elif root_status == "completed":
                scan_state = "failed"
                self.controller.error = "Scan ended without a completed report"
            elif root_status == "budget_paused":
                scan_state = "budget_paused"
            elif root_status == "waiting":
                scan_state = {
                    "provider": "waiting_provider",
                    "blocked": "blocked",
                    "user": "waiting_user",
                    "agents": "waiting_agents",
                    "stalled": "blocked",
                }.get(root_wait_kind, "queued")
            elif root_status == "running":
                root_operation = (
                    self.coordinator.metadata.get(root_id, {}).get("operation") if root_id else None
                )
                scan_state = (
                    str(root_operation)
                    if root_operation in {"queued", "retrying", "compacting"}
                    else "running"
                )
        if scan_state != self.controller.scan_state:
            self.controller.scan_state = scan_state
            changed = True
        return changed

    def _runtime_sync_fingerprint(self) -> str:
        usage: dict[str, Any] = {}
        vulnerabilities: list[object] = []
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
            vulnerabilities = [
                (report.get("id", index), _revision_count(report))
                if isinstance(report, dict)
                else index
                for index, report in enumerate(self.report_state.vulnerability_reports)
            ]
        return json.dumps(
            {
                "scan_state": self.controller.scan_state,
                "usage": usage,
                "vulnerabilities": vulnerabilities,
            },
            default=str,
            sort_keys=True,
            separators=(",", ":"),
        )

    async def sync_state(self) -> None:
        while True:
            if self.scan_task is not None and not self.scan_task.done():
                try:
                    changed = await self._sync_agent_state()
                except Exception as exc:
                    logger.exception("Go TUI agent-state sync failed")
                    self.controller.error = f"Agent-state sync failed: {exc}"
                    changed = True
                fingerprint = self._runtime_sync_fingerprint()
                if fingerprint != self._last_sync_fingerprint:
                    self._last_sync_fingerprint = fingerprint
                    changed = True
                if changed:
                    self.controller.notify_changed()
            await asyncio.sleep(0.5)

    async def quit(self) -> None:
        self.controller.close_viewer()
        self.coordinator.mark_shutting_down()
        scan_task = self.scan_task
        if scan_task is not None:
            if not scan_task.done():
                scan_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scan_task
        if self.run_lease is not None:
            self.run_lease.close()
            self.run_lease = None


class GoTuiRuntime(WorkspaceRuntime):
    def __init__(self, args: LaunchState) -> None:
        super().__init__(args)
        self.server = TuiBackendServer(self.controller)

    @staticmethod
    def binary_command() -> list[str]:
        source = tui_source_dir()
        # A checkout may also contain a stale wheel/build sidecar. Running the
        # current source is the deterministic development choice.
        if (source / "go.mod").is_file() and shutil.which("go"):
            return ["go", "run", "./cmd/strix-tui"]
        packaged = get_strix_resource_path("bin", tui_executable())
        if packaged.is_file():
            return [str(packaged)]
        raise RuntimeError(
            "Bubble Tea TUI binary not found. Reinstall Strix from an official platform wheel."
        )

    @staticmethod
    async def _cancel_tasks(*tasks: asyncio.Task[None] | None) -> None:
        for task in tasks:
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def run(self) -> ReportState | None:
        # Redirect the process's sys.stdout/sys.stderr while the TUI runs so
        # logging handlers created during the scan never paint over the Go
        # TUI's alt screen. The child still inherits the real terminal fds;
        # only the Python-level bindings change.
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        loop = asyncio.get_running_loop()
        output_sink = WorkspaceOutput(
            lambda line: loop.call_soon_threadsafe(self.controller.record_output, line)
        )
        sys.stdout = output_sink
        sys.stderr = output_sink
        backend_socket: socket.socket | None = None
        sync_task: asyncio.Task[None] | None = None
        prepare_task: asyncio.Task[None] | None = None
        process: asyncio.subprocess.Process | subprocess.Popen[bytes] | None = None
        try:
            env = child_environment()
            env["STRIX_VERSION"] = package_version()
            command = self.binary_command()
            cwd = str(tui_source_dir()) if command[:2] == ["go", "run"] else None
            if cwd is not None:
                # go run compiles the sidecar when the build cache is cold, so
                # tell the terminal why nothing is on screen yet.
                _print_compile_notice(original_stdout)
            process, backend_socket = await launch_tui_process(command, env, cwd)
            await self.server.start(backend_socket)
            prepare_task = self._start_preparation()
            sync_task = asyncio.create_task(self.sync_state())
            return_code = await wait_process(process)
            check_return_code(return_code)
        except Exception as exc:
            await terminate_process(process)
            if not self.server.activated:
                raise GoTuiPreActivationError(str(exc)) from exc
            raise
        except BaseException:
            await terminate_process(process)
            raise
        finally:
            try:
                if backend_socket is not None:
                    backend_socket.close()
                await self._cancel_tasks(prepare_task, sync_task)
                await self.quit()
                await self.server.close()
                self.controller.close()
            finally:
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                output_sink.close()
        # Mirror run_tui: surface the captured scan failure once the app has
        # exited cleanly so the CLI reports it instead of exiting 0.
        if self.scan_error is not None:
            raise self.scan_error
        return self.report_state


async def run_go_tui(args: LaunchState) -> ReportState | None:
    return await GoTuiRuntime(args).run()
