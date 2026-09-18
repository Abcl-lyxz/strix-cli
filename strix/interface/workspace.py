"""Shared workspace operations; transport and rendering are client concerns."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from rich.console import Console

from strix.config.app_config import get_config_service
from strix.config.runtime_routes import load_app_routes
from strix.config.ui import settings_fields, update_setting
from strix.core.paths import runs_base_dir
from strix.interface.attachments import complete_paths, describe_attachment
from strix.interface.connections import connections, update_connection
from strix.interface.scan_setup import preflight_model_connection
from strix.interface.viewer.server import build_runs_payload
from strix.providers import get_provider_registry
from strix.providers.policy import quality_tier


if TYPE_CHECKING:
    from strix.interface.application import ApplicationController
    from strix.interface.application_runtime import WorkspaceRuntime


class WorkspaceCommands:
    def __init__(self, controller: ApplicationController) -> None:
        self.controller = controller
        self.runtime: WorkspaceRuntime | None = None
        self.attachments: list[dict[str, Any]] = []
        self.pending_attachment_ids: list[str] = []
        self.results: dict[str, dict[str, Any]] = {}
        self.command_lock = asyncio.Lock()
        self.recent_cache: tuple[float, list[dict[str, Any]]] = (0.0, [])

    def recent_sessions(self) -> list[dict[str, Any]]:
        if time.monotonic() - self.recent_cache[0] < 5:
            return self.recent_cache[1]
        root = runs_base_dir()
        entries: list[dict[str, Any]] = []
        try:
            paths = sorted(root.glob("*/run.json"), key=lambda p: p.stat().st_mtime, reverse=True)[
                :5
            ]
            for path in paths:
                record = json.loads(path.read_text(encoding="utf-8"))
                entries.append(
                    {"name": path.parent.name, "status": record.get("status", "unknown")}
                )
        except (OSError, ValueError):
            pass
        self.recent_cache = (time.monotonic(), entries)
        return entries

    def public_attachments(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in item.items() if k != "files"} for item in self.attachments]

    async def handle(  # noqa: PLR0911, PLR0912, PLR0915 - shared command dispatch
        self, command: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        c = self.controller
        if command == "settings.list":
            return {"fields": settings_fields()}
        if command == "settings.update":
            return update_setting(
                str(payload.get("id", "")),
                payload.get("value"),
            )
        if command == "mcp.list":
            return {"connections": connections()}
        if command == "mcp.update":
            return update_connection(payload)
        if command == "notifications.preferences":
            c.notification_service.set_preference(
                str(payload.get("category") or "runtime"),
                minimum_severity=payload.get("minimum_severity", "warning"),
                immediate=payload.get("immediate") is True,
            )
            return {"saved": True}
        if command == "update.start":
            if c.scan_started and c.scan_state not in {"completed", "failed", "stopped"}:
                raise RuntimeError("An update cannot be installed during an active scan")
            from strix.interface.update_check import self_update  # noqa: PLC0415

            output = io.StringIO()
            succeeded = await asyncio.to_thread(
                self_update,
                Console(file=output, color_system=None, force_terminal=False),
                scan_status=c.scan_state,
            )
            message = output.getvalue().strip() or (
                "Update ready; restart Strix" if succeeded else "Update failed"
            )
            return {"updated": succeeded, "message": message[-1_000:]}
        if command == "doctor.run":
            from strix.interface.doctor import collect_diagnostics  # noqa: PLC0415

            report = await asyncio.to_thread(collect_diagnostics, check_network=False)
            checks = report.get("checks", []) if isinstance(report, dict) else []
            failed = [item for item in checks if isinstance(item, dict) and not item.get("ok")]
            return {
                "ok": bool(report.get("ok")) if isinstance(report, dict) else False,
                "report": report,
                "message": (
                    "Doctor checks passed"
                    if not failed
                    else (
                        f"Doctor found {len(failed)} issue(s); "
                        "use `strix doctor --network` for details"
                    )
                ),
            }
        if command == "providers.list":
            config = get_config_service().load()
            registry = get_provider_registry()
            detected = registry.detected_connections()
            detected_provider_ids = {item.provider_id for item in detected}
            providers = []
            for definition in registry.definitions():
                item = definition.model_dump(mode="json")
                if definition.id in detected_provider_ids:
                    item["auth_methods"] = [
                        "environment",
                        *[method for method in item["auth_methods"] if method != "environment"],
                    ]
                    item["detected"] = True
                providers.append(item)
            return {
                "providers": providers,
                "connections": [
                    item.model_dump(mode="json") for item in config.connections.values()
                ],
                "detected_connections": [item.model_dump(mode="json") for item in detected],
                "models": [item.model_dump(mode="json") for item in config.models.values()],
            }
        if command == "providers.connect":
            provider_id = str(payload.get("provider_id") or "")
            adapter = get_provider_registry().adapter(provider_id)
            profile = await asyncio.to_thread(adapter.connect, payload)
            if self.runtime is not None:
                self.runtime.model_verified = False
            return {"connection": profile.model_dump(mode="json"), "saved": True}
        if command == "providers.disconnect":
            connection_id = str(payload.get("connection_id") or "")
            if not connection_id:
                raise ValueError("connection_id is required")
            config = get_config_service().load()
            connection = config.connections.get(connection_id)
            if connection is None:
                raise ValueError(f"Unknown connection: {connection_id}")
            disconnected = await asyncio.to_thread(
                get_provider_registry().adapter(connection.provider_id).disconnect,
                connection_id,
            )
            return {"disconnected": disconnected}
        if command in {"models.list", "models.discover"}:
            config = get_config_service().load()
            connection_id = str(payload.get("connection_id") or "")
            if command == "models.discover":
                if not connection_id:
                    raise ValueError("Choose a provider connection first")
                connection = config.connections.get(connection_id)
                if connection is None:
                    raise ValueError(f"Unknown connection: {connection_id}")
                adapter = get_provider_registry().adapter(connection.provider_id)
                models = await asyncio.to_thread(
                    adapter.discover_models,
                    connection,
                    refresh=payload.get("refresh") is True,
                )
                if models:
                    config = get_config_service().upsert_models(models)
            visible_connections = list(config.connections.values())
            visible_models = list(config.models.values())
            if connection_id:
                visible_connections = [
                    item for item in visible_connections if item.id == connection_id
                ]
                visible_models = [
                    item for item in visible_models if item.connection_id == connection_id
                ]
            return {
                "connections": [item.model_dump(mode="json") for item in visible_connections],
                "models": [item.model_dump(mode="json") for item in visible_models],
            }
        if command == "models.toggle":
            model_id = str(payload.get("model_id") or "")
            enabled = payload.get("enabled")
            if not model_id or not isinstance(enabled, bool):
                raise ValueError("model_id and boolean enabled are required")
            config = get_config_service().load()
            descriptor = config.models.get(model_id)
            if descriptor is None:
                raise ValueError(f"Unknown model: {model_id}")
            descriptor_changed = False
            inferred_tier = quality_tier(
                descriptor.provider_id,
                descriptor.adapter_id,
                descriptor.model_id,
            )
            if descriptor.quality_tier == "unknown" and inferred_tier != "unknown":
                descriptor = descriptor.model_copy(update={"quality_tier": inferred_tier})
                descriptor_changed = True
            if enabled and (
                descriptor.supports_tools is not True
                or descriptor.context_window_tokens is None
                or descriptor.metadata_confidence == "unknown"
            ):
                connection = config.connections.get(descriptor.connection_id)
                if connection is None:
                    raise ValueError("The model connection no longer exists")
                adapter = get_provider_registry().adapter(connection.provider_id)
                verification = await asyncio.to_thread(
                    adapter.verify_capabilities,
                    connection,
                    descriptor,
                )
                descriptor = descriptor.model_copy(
                    update={
                        "supports_tools": (
                            verification.supports_tools
                            if verification.supports_tools is not None
                            else descriptor.supports_tools
                        ),
                        "supports_vision": (
                            verification.supports_vision
                            if verification.supports_vision is not None
                            else descriptor.supports_vision
                        ),
                        "context_window_tokens": (
                            verification.context_window_tokens or descriptor.context_window_tokens
                        ),
                        "max_output_tokens": (
                            verification.max_output_tokens or descriptor.max_output_tokens
                        ),
                        "metadata_source": verification.source,
                    }
                )
                if descriptor.supports_tools is False:
                    raise ValueError(
                        "This model declares that tool calling is unsupported and cannot run "
                        "Strix agents"
                    )
                if (
                    descriptor.supports_tools is not True
                    or descriptor.context_window_tokens is None
                    or descriptor.metadata_confidence not in {"verified", "catalog"}
                ):
                    route = adapter.build_model(connection, descriptor)
                    route.supports_tools = descriptor.supports_tools
                    route.supports_vision = descriptor.supports_vision
                    route.supports_reasoning = descriptor.supports_reasoning
                    route.quality_tier = descriptor.quality_tier
                    route.input_cost_per_million = descriptor.input_cost_per_million
                    route.output_cost_per_million = descriptor.output_cost_per_million
                    live = await preflight_model_connection(
                        route.model,
                        check_tools=True,
                        routes_override=[route],
                        allow_unverified=True,
                    )
                    descriptor = descriptor.model_copy(
                        update={
                            "supports_tools": live.supports_tools,
                            "supports_vision": (
                                live.supports_vision
                                if live.supports_vision is not None
                                else descriptor.supports_vision
                            ),
                            # Unknown gateways are deliberately capped at the
                            # conservative context fallback returned by the live
                            # probe.  The compactor can now act before overflow
                            # instead of blocking an otherwise working model.
                            "context_window_tokens": live.context_window_tokens,
                            "max_output_tokens": live.max_output_tokens,
                            "metadata_source": live.source,
                            "metadata_confidence": "verified",
                            "verified_at": datetime.now(UTC).isoformat(),
                        }
                    )
                if descriptor.supports_tools is not True:
                    raise ValueError("The live model probe did not confirm tool calling support")
                get_config_service().upsert_models([descriptor])
                descriptor_changed = False
            if descriptor_changed:
                get_config_service().upsert_models([descriptor])
            model = get_config_service().set_model_enabled(model_id, enabled)
            return {"model": model.model_dump(mode="json")}
        if command == "router.status":
            config = get_config_service().load()
            pool = getattr(c.scan_context, "route_pool", None) if c.scan_context else None
            decision = getattr(pool, "last_decision", None)
            try:
                configured_routes = [route.public_dict() for route in load_app_routes()]
            except ValueError:
                configured_routes = []
            return {
                "policy": config.router.model_dump(mode="json"),
                "routes": pool.public_status() if pool is not None else configured_routes,
                "decision": {
                    "route_id": decision.route_id,
                    "model": decision.model,
                    "reason": decision.reason,
                    "rejected": decision.rejected,
                }
                if decision is not None
                else None,
            }
        if command == "providers.test":
            await preflight_model_connection(
                "",
                check_tools=True,
            )
            return {"verified": True, "tools": True}
        if command == "paths.complete":
            return {"paths": await asyncio.to_thread(complete_paths, str(payload.get("query", "")))}
        if command == "attachments.list":
            return {"attachments": self.public_attachments()}
        if command == "attachments.add":
            item = await asyncio.to_thread(
                describe_attachment,
                str(payload.get("path", "")),
                role=str(payload.get("role", "context")),
            )
            if any(
                existing["path"] == item["path"] and existing["role"] == item["role"]
                for existing in self.attachments
            ):
                return {"attachments": self.public_attachments()}
            if c.scan_started and not c.setup_mode:
                if item["role"] == "target":
                    raise ValueError(
                        "Use supporting context during a scan, "
                        "or start a new scan to change targets"
                    )
                await self.stage_live(item)
            else:
                files = list(getattr(c.args, "workspace_files", []) or [])
                files.extend(item["files"])
                c.args.workspace_files = files
            self.attachments.append(item)
            if item["role"] == "target" and item["path"] not in c.targets:
                c.targets.append(item["path"])
                c.args.targets_info.append(
                    {
                        "type": "local_file",
                        "original": item["path"],
                        "details": {
                            "target_path": item["path"],
                            "workspace_path": item["workspace_path"],
                        },
                    }
                )
                item["added_target"] = True
            self.pending_attachment_ids.append(item["id"])
            return {
                "attachment": {k: v for k, v in item.items() if k != "files"},
                "attachments": self.public_attachments(),
            }
        if command == "attachments.remove":
            identifier = str(payload.get("id", ""))
            removed = next((item for item in self.attachments if item["id"] == identifier), None)
            if removed:
                self.attachments.remove(removed)
                if removed.get("added_target") and c.setup_mode:
                    c.targets = [t for t in c.targets if t != removed["path"]]
                    c.args.targets_info = [
                        t for t in c.args.targets_info if t.get("original") != removed["path"]
                    ]
                self.pending_attachment_ids = [
                    i for i in self.pending_attachment_ids if i != identifier
                ]
                if c.setup_mode:
                    c.args.workspace_files = [
                        f
                        for f in getattr(c.args, "workspace_files", [])
                        if f not in removed["files"]
                    ]
            return {"attachments": self.public_attachments()}
        if command == "sessions.list":
            return build_runs_payload(runs_base_dir(), verified=True)
        if command == "scan.stop":
            if self.runtime is not None and self.runtime.scan_task is not None:
                self.runtime.scan_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self.runtime.scan_task
            return {"stopped": True}
        if command in {"scan.new", "scan.resume"}:
            if self.runtime is None:
                raise RuntimeError("Scan management is unavailable in this viewer")
            await self.runtime.new_session(
                str(payload.get("run", "")) if command == "scan.resume" else ""
            )
            return {"ready": True}
        if command == "scan.submit":
            message = c.prompt_text(payload, "message")
            if not c.setup_mode:
                agent = str(payload.get("agent_id") or next(iter(c.live_view.agents), ""))
                return await c.handle("agent.send_message", {"agent_id": agent, "message": message})
            await asyncio.to_thread(self.validate_attachments)
            c.instruction = message + self.attachment_context()
            target = payload.get("target")
            if not target:
                standalone = message.strip().strip("\"'")
                try:
                    path = Path(standalone).expanduser()
                    if ("\n" not in standalone and path.exists()) or (
                        standalone.startswith(("http://", "https://"))
                        and not any(char.isspace() for char in standalone)
                    ):
                        target = standalone
                except (OSError, ValueError):
                    pass
            if isinstance(target, str) and target.strip():
                await c.handle("setup.add_target", {"target": target.strip()})
            # Explicit attachments provide a workspace without a blanket cwd mount.
            result = await c.handle("setup.start", {"mount_working_dir": not c.targets})
            if c.pending_workspace_mount and self.attachments:
                await c.handle("setup.confirm_mount", {"approved": False})
            self.pending_attachment_ids.clear()
            return result
        raise ValueError(f"Unknown command: {command}")

    def validate_attachments(self) -> None:
        for item in self.attachments:
            total = 0
            for entry in item["files"]:
                path = Path(entry["source_path"])
                total += path.stat().st_size
                if total > 250 * 1024 * 1024:
                    raise ValueError(f"Attachment grew beyond 250 MiB: {item['name']}")
                with path.open("rb"):
                    pass

    def attachment_context(self) -> str:
        selected = [a for a in self.attachments if a["id"] in self.pending_attachment_ids]
        if not selected:
            return ""
        return "\n\nExplicit attachments available in the sandbox:\n" + "\n".join(
            f"- {a['role']}: {a['name']} -> {a['workspace_path']}" for a in selected
        )

    async def stage_live(self, item: dict[str, Any]) -> None:
        scan_context = self.controller.scan_context
        session = scan_context.sandbox_session if scan_context is not None else None
        if session is None:
            raise RuntimeError("Sandbox is not ready; attachment was not sent")
        for entry in item["files"]:
            destination = entry["workspace_path"]
            result = await session.exec("mkdir", "-p", destination.rsplit("/", 1)[0])
            if not result.ok():
                raise RuntimeError("Cannot create attachment directory in sandbox")
            content = await asyncio.to_thread(Path(entry["source_path"]).read_bytes)
            await session.write(Path(destination), io.BytesIO(content))
            await session.exec("chmod", "0444", destination)

    async def dispatch(
        self, command: str, payload: dict[str, Any], request_id: str = ""
    ) -> dict[str, Any]:
        """Serialize mutations across clients and replay acknowledged results."""
        async with self.command_lock:
            fingerprint = hashlib.sha256(
                json.dumps([command, payload], sort_keys=True, default=str).encode()
            ).hexdigest()
            if request_id in self.results:
                prior = self.results[request_id]
                if prior["fingerprint"] != fingerprint:
                    raise ValueError("Request ID was reused for a different command")
                return cast("dict[str, Any]", prior["result"])
            result = await self.controller.handle(command, payload)
            if request_id:
                self.results[request_id] = {"fingerprint": fingerprint, "result": result}
                while len(self.results) > 1000:
                    self.results.pop(next(iter(self.results)))
            return result
