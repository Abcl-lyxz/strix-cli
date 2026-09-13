"""Shared workspace operations; transport and rendering are client concerns."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from strix.config.providers import (
    PROVIDERS,
    connect_provider,
    discover_models,
    profile_list,
    update_route_options,
)
from strix.config.ui import settings_fields, update_setting
from strix.core.paths import runs_base_dir
from strix.interface.attachments import complete_paths, describe_attachment
from strix.interface.connections import connections, update_connection


if TYPE_CHECKING:
    from strix.interface.application_runtime import WorkspaceRuntime
    from strix.interface.tui.backend.controller import TuiController


class WorkspaceCommands:
    def __init__(self, controller: TuiController) -> None:
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
            field = str(payload.get("id", ""))
            if field in {"llm.model", "llm.api_key", "llm.api_base"}:
                return await c.handle(
                    "config.update",
                    {
                        field.split(".")[1]: payload.get("value"),
                        "persist": payload.get("persist") is True,
                    },
                )
            return update_setting(
                str(payload.get("id", "")),
                payload.get("value"),
                persist=payload.get("persist") is True,
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
        if command == "providers.list":
            return {
                "providers": PROVIDERS,
                "profiles": profile_list(),
                "selected": c.selected_route,
            }
        if command == "providers.discover":
            return await asyncio.to_thread(
                discover_models,
                str(payload.get("provider_id", "custom")),
                base_url=str(payload.get("base_url") or ""),
                api_key=str(payload.get("api_key") or ""),
                profile=str(payload.get("profile") or ""),
                refresh=payload.get("refresh") is True,
            )
        if command == "providers.connect":
            result = await asyncio.to_thread(connect_provider, payload)
            c.selected_route = result["name"]
            c.args.route = [c.selected_route]
            if self.runtime is not None:
                self.runtime.model_verified = False
            return result
        if command == "providers.advanced":
            return update_route_options(payload)
        if command == "providers.test":
            from strix.interface.scan_setup import (
                preflight_model_connection,
            )

            await preflight_model_connection(
                "",
                selected_routes=[c.selected_route] if c.selected_route else None,
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
            from strix.interface.viewer.server import (
                build_runs_payload,
            )

            return build_runs_payload(runs_base_dir(), verified=True)
        if command == "scan.stop":
            if self.runtime is not None and self.runtime.scan_task is not None:
                self.runtime.scan_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self.runtime.scan_task
            return {"stopped": True}
        if command == "scan.retry":
            agent = str(payload.get("agent_id") or next(iter(c.live_view.agents), ""))
            return await c.handle(
                "agent.send_message",
                {
                    "agent_id": agent,
                    "message": (
                        "Retry the interrupted turn using the saved results. "
                        "Do not repeat completed tool actions."
                    ),
                },
            )
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
        from strix.runtime.session_manager import (
            cached_session,
        )

        bundle = cached_session(str(self.controller.args.run_name))
        if not bundle:
            raise RuntimeError("Sandbox is not ready; attachment was not sent")
        session = bundle["session"]
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
