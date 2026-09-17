"""Thread-safe, read-only live snapshot adapter for the browser viewer."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

from strix.security.secrets import redact_secrets


if TYPE_CHECKING:
    from pathlib import Path


def public_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [public_value(item) for item in cast("list[object]", value)]
    if isinstance(value, dict):
        return {key: public_value(item) for key, item in cast("dict[str, Any]", value).items()}
    return value


class BrowserWorkspace:
    def __init__(
        self, controller: Any, loop: asyncio.AbstractEventLoop, *, initial_run: str | None = None
    ) -> None:
        self.controller = controller
        self.loop = loop
        self.closed = False
        self.initial_run = initial_run

    def run_dir(self) -> Path | None:
        report = self.controller.report_state
        return report.get_run_dir() if report is not None else None

    def snapshot(self, cursor: int | None = None) -> dict[str, Any]:
        async def collect() -> dict[str, Any]:
            c = self.controller
            if cursor is None:
                next_cursor, events = c.collection_snapshot("events")
            else:
                next_cursor, events = c.collection_changes("events", cursor)
            state = c.snapshot()
            state.pop("viewer_url", None)
            directory = self.run_dir()
            state["run_name"] = directory.name if directory else None
            return cast(
                "dict[str, Any]",
                public_value(
                    {
                        "state": state,
                        "agents": c.collection("agents"),
                        "events": events,
                        "reset": cursor is None,
                        "cursor": next_cursor,
                        "findings": c.collection("vulnerabilities"),
                        "attachments": c.workspace.public_attachments(),
                    }
                ),
            )

        return asyncio.run_coroutine_threadsafe(collect(), self.loop).result(timeout=15)
