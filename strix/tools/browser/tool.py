"""Structured adapter for the sandbox's pinned agent-browser executable."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import io
import json
import time
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import uuid4

from agents import RunContextWrapper, function_tool

from strix.core.paths import run_dir_for
from strix.llm.error_envelope import error_envelope
from strix.security import get_secret_store, redact_secrets
from strix.security.secrets import redact_value


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


_READS = {"snapshot", "tabs", "console", "errors", "network", "title", "url"}


class BrowserSession:
    def __init__(self, context: dict[str, Any]) -> None:
        self.scan_id = str(context["scan_id"])
        self.agent_id = str(context["agent_id"])
        self.sandbox = context["sandbox_session"]
        identity = hashlib.sha256(f"{self.scan_id}:{self.agent_id}".encode()).hexdigest()[:24]
        self.name = f"strix-{identity}"
        self.secret_ref = f"browser.{identity}.state"
        self.lock = asyncio.Lock()
        self.last_used = time.monotonic()

    async def execute(self, arguments: list[str]) -> dict[str, Any]:
        result = await self.sandbox.exec(
            "agent-browser", "--session", self.name, "--json", *arguments, timeout=35
        )
        stdout = (
            result.stdout.decode("utf-8", "replace")
            if isinstance(result.stdout, bytes)
            else str(result.stdout)
        )
        stderr = (
            result.stderr.decode("utf-8", "replace")
            if isinstance(result.stderr, bytes)
            else str(result.stderr)
        )
        try:
            payload = json.loads(stdout)
        except ValueError:
            payload = {"output": stdout[-32000:]}
        if not isinstance(payload, dict):
            payload = {"output": payload}
        payload = cast("dict[str, Any]", payload)
        return {
            **payload,
            "success": result.ok() and payload.get("success", True),
            "error": payload.get("error") or (stderr[-4000:] if not result.ok() else None),
        }

    async def action(self, action: str, selector: str, value: str) -> dict[str, Any]:
        async with self.lock:
            idle = time.monotonic() - self.last_used > 175
            self.last_used = time.monotonic()
            if action in {"save_state", "load_state"}:
                return await self.state(action)
            arguments, artifact = self.arguments(action, selector, value)
            if artifact:
                await self.sandbox.exec("mkdir", "-p", "/workspace/.strix-browser")
            result = await self.execute(arguments)
            recovered = False
            if not result["success"] and action in _READS:
                result = await self.execute(arguments)
                recovered = bool(result["success"])
            if not result["success"]:
                detail = str(result.get("error", ""))
                result["recovery"] = (
                    "Refresh the snapshot and choose a current reference; "
                    "the action was not replayed."
                    if any(word in detail.lower() for word in ("ref", "selector", "element", "tab"))
                    else "Browser unavailable. Open the page again and restore saved state; "
                    "the action was not replayed."
                )
            if artifact and result["success"]:
                result["artifact"] = await self.export(artifact)
            if idle:
                result["session_notice"] = (
                    "The idle browser may have been reclaimed. "
                    "Check the URL and authentication before continuing."
                )
            if recovered:
                result["recovery"] = "Read succeeded after retry"
            result.update({"action": action, "session": self.name})
            return cast("dict[str, Any]", redact_value(result))

    @staticmethod
    def arguments(  # noqa: PLR0911, PLR0912 - bounded action allowlist
        action: str, selector: str, value: str
    ) -> tuple[list[str], str | None]:
        if any("\0" in item for item in (selector, value)):
            raise ValueError("Browser parameters cannot contain NUL bytes")
        if selector.startswith("-") or value.startswith("--session"):
            raise ValueError("Browser parameters cannot override session ownership")
        reads = {
            "snapshot": ["snapshot", "-i"],
            "tabs": ["tab"],
            "console": ["console"],
            "errors": ["errors"],
            "network": ["network", "requests"],
            "title": ["get", "title"],
            "url": ["get", "url"],
            "close": ["close"],
        }
        if action in reads:
            return reads[action], None
        if action in {"open", "new_tab"}:
            if not value.startswith(("http://", "https://", "about:blank")):
                raise ValueError("Navigation requires an HTTP(S) URL or about:blank")
            return (["open", value] if action == "open" else ["tab", "new", value]), None
        if action in {"switch_tab", "close_tab"}:
            if not value.isdecimal():
                raise ValueError("Choose a tab number from the tabs action")
            return (["tab", value] if action == "switch_tab" else ["tab", "close", value]), None
        if action in {"click", "hover", "check", "uncheck"}:
            if not selector:
                raise ValueError("A current reference or selector is required")
            return [action, selector], None
        if action in {"fill", "select", "type"}:
            if not selector:
                raise ValueError("A current reference or selector is required")
            return [action, selector, value], None
        if action == "press":
            return ["press", value], None
        if action == "wait":
            return (["wait", selector] if selector else ["wait", "--text", value]), None
        if action == "upload":
            upload_path = PurePosixPath(value)
            if not upload_path.is_relative_to("/workspace") or ".." in upload_path.parts:
                raise ValueError("Upload a file staged under /workspace")
            return ["upload", selector, str(upload_path)], None
        if action in {"screenshot", "download"}:
            suffix = ".png" if action == "screenshot" else ".download"
            path = f"/workspace/.strix-browser/{uuid4().hex}{suffix}"
            return (
                ["screenshot", path] if action == "screenshot" else ["download", selector, path]
            ), path
        raise ValueError("Unknown browser action")

    async def export(self, source: str) -> dict[str, str]:
        stream = await self.sandbox.read(Path(source))
        content = stream.read(50 * 1024 * 1024 + 1)
        if len(content) > 50 * 1024 * 1024:
            raise ValueError("Browser artifact exceeds 50 MiB; it remains in the sandbox")
        name = PurePosixPath(source).name
        destination = run_dir_for(self.scan_id) / "browser" / self.name / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(destination.write_bytes, content)
        return {"path": f"browser/{self.name}/{name}", "sandbox_path": source}

    async def state(self, action: str) -> dict[str, Any]:
        directory = f"/workspace/.strix-browser-state-{uuid4().hex}"
        created = await self.sandbox.exec("mkdir", "-m", "0700", directory)
        if not created.ok():
            raise RuntimeError("Cannot create a private browser state directory")
        path = directory + "/state.json"
        store = get_secret_store()
        try:
            if action == "save_state":
                result = await self.execute(["state", "save", path])
                if not result["success"]:
                    return result
                await self.sandbox.exec("chmod", "0600", path)
                stream = await self.sandbox.read(Path(path))
                content = stream.read(1024 * 1024 + 1)
                if len(content) > 1024 * 1024:
                    raise ValueError("Browser state exceeds 1 MiB")
                await asyncio.to_thread(store.set, self.secret_ref, content.decode("utf-8"))
            else:
                saved = await asyncio.to_thread(store.get, self.secret_ref)
                if not saved:
                    return {
                        "success": False,
                        "error": "No saved state for this agent; authenticate again",
                    }
                await self.sandbox.write(Path(path), io.BytesIO(saved.encode("utf-8")))
                await self.sandbox.exec("chmod", "0600", path)
                result = await self.execute(["state", "load", path])
                if not result["success"]:
                    return {
                        "success": False,
                        "error": "Saved authentication could not be restored; authenticate again",
                    }
            return {
                "success": True,
                "action": action,
                "session": self.name,
                "notice": (
                    "Saved cookies may expire; confirm the authenticated page before continuing."
                ),
            }
        finally:
            await self.sandbox.exec("rm", "-f", path)
            await self.sandbox.exec("rmdir", directory)


async def close_browser(context: dict[str, Any]) -> None:
    scan_context = context.get("scan_context")
    if scan_context is None:
        return
    sessions = scan_context.runtime_resource("browser_sessions", dict)
    browser = sessions.pop(str(context.get("agent_id")), None)
    if browser is not None:
        with contextlib.suppress(Exception):
            async with browser.lock:
                await browser.execute(["close"])


@function_tool
async def browser_action(
    ctx: RunContextWrapper,
    action: Literal[
        "open",
        "snapshot",
        "tabs",
        "new_tab",
        "switch_tab",
        "close_tab",
        "click",
        "fill",
        "type",
        "select",
        "hover",
        "check",
        "uncheck",
        "press",
        "wait",
        "upload",
        "download",
        "screenshot",
        "console",
        "errors",
        "network",
        "title",
        "url",
        "save_state",
        "load_state",
        "close",
    ],
    selector: str = "",
    value: str = "",
) -> dict[str, Any]:
    """Use your isolated browser. Refresh snapshots after navigation or interaction.

    Args:
        action: Browser operation. Consequential actions are never automatically replayed.
        selector: Current @eN reference or CSS selector for interaction and upload/download.
        value: URL, input text, key name, tab number, wait text, or sandbox upload path.
    """
    raw_context: object = ctx.context
    if not isinstance(raw_context, dict):
        return {"success": False, "error": "An agent-owned sandbox is required"}
    context = cast("dict[str, Any]", raw_context)
    if not all(context.get(k) for k in ("scan_id", "agent_id", "sandbox_session", "scan_context")):
        return {"success": False, "error": "An agent-owned sandbox is required"}
    sessions = cast(
        "dict[str, BrowserSession]",
        context["scan_context"].runtime_resource("browser_sessions", dict),
    )
    agent_id = str(context["agent_id"])
    browser = sessions.setdefault(agent_id, BrowserSession(context))
    try:
        return await browser.action(action, selector, value)
    except (ValueError, OSError, TimeoutError, RuntimeError) as exc:
        envelope = (
            error_envelope(exc, category_hint="tool_validation", safe_to_replay=action in _READS)
            if isinstance(exc, ValueError)
            else error_envelope(exc, category_hint="browser_proxy", safe_to_replay=action in _READS)
        )
        return {
            "success": False,
            "action": action,
            "error": redact_secrets(exc),
            "error_envelope": envelope.to_dict(),
            "recovery": "The action was not replayed. Inspect the page before trying again.",
        }


def browser_lifecycle[**P, R](function: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
    @functools.wraps(function)
    async def run(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return await function(*args, **kwargs)
        finally:
            context = kwargs.get("context", {})
            if isinstance(context, dict):
                await close_browser(cast("dict[str, Any]", context))

    return run
