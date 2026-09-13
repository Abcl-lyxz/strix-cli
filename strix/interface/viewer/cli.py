"""`strix view [<run>]` command: serve a run's viewer UI locally."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from rich.console import Console

from strix.core.paths import (
    RUNS_DIR_NAME,
    latest_run_dir,
    run_dir_for,
    run_record_path,
    runs_base_dir,
)
from strix.interface.viewer.server import authorized_url, bundle_is_built, serve


if TYPE_CHECKING:
    from pathlib import Path
    from typing import NoReturn


logger = logging.getLogger(__name__)


def run_view(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="strix view",
        description="Open a local web view of a Strix run (live or finished).",
    )
    parser.add_argument(
        "run",
        nargs="?",
        default=None,
        help=f"Run name under ./{RUNS_DIR_NAME} (defaults to the most recent run).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port to serve on (default: an available ephemeral port).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1; use 0.0.0.0 for all IPv4 interfaces).",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the browser automatically.",
    )
    args = parser.parse_args(argv)

    console = Console()

    if not bundle_is_built():
        console.print(
            "[bold red]Viewer UI is not built.[/]\n"
            "Build it with: [cyan]cd strix/interface/viewer/frontend && npm ci && npm run build[/]"
        )
        raise SystemExit(1)

    run_dir = _resolve_run_dir(args.run, console)

    async def workspace() -> None:
        from strix.interface.application_runtime import WorkspaceRuntime
        from strix.interface.cli_args import parse_arguments
        from strix.interface.output import WorkspaceOutput
        from strix.interface.viewer.workspace import BrowserWorkspace

        runtime = WorkspaceRuntime(parse_arguments([]))
        runtime.controller.scan_loop = asyncio.get_running_loop()
        bridge = BrowserWorkspace(
            runtime.controller, asyncio.get_running_loop(), initial_run=args.run
        )
        httpd, url, token = serve(
            run_dir, host=args.host, port=args.port, open_browser=not args.no_open, workspace=bridge
        )
        sync = asyncio.create_task(runtime.sync_state())
        console.print("Local Strix workspace:")
        console.print(authorized_url(url, token), soft_wrap=True, markup=False)
        console.print("Press Ctrl-C to stop the workspace.")
        loop = asyncio.get_running_loop()
        output = WorkspaceOutput(
            lambda line: loop.call_soon_threadsafe(runtime.controller.record_output, line)
        )
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                await asyncio.Event().wait()
        finally:
            bridge.closed = True
            await asyncio.to_thread(httpd.shutdown)
            httpd.server_close()
            sync.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sync
            await runtime.quit()
            output.close()
            await asyncio.sleep(0)  # Deliver the final flushed output before closing subscribers.
            runtime.controller.close()

    try:
        asyncio.run(workspace())
    except KeyboardInterrupt:
        console.print("Workspace stopped.")


def state_label(summary: dict[str, object]) -> str:
    if not summary.get("finished", False):
        return "[#eab308]live[/]"

    status = summary.get("status")
    if status == "failed":
        return "[#ef4444]failed[/]"
    if status in {"stopped", "interrupted"}:
        return f"[#eab308]{status}[/]"
    return "[#22c55e]finished[/]"


_state_label = state_label  # Compatibility for existing local integrations.


def _resolve_run_dir(run: str | None, console: Console) -> Path:
    if run:
        run_dir = run_dir_for(run)
        if not run_record_path(run_dir).is_file():
            _fail_no_run(console, requested=run)
        return run_dir

    latest = latest_run_dir()
    return latest if latest is not None else runs_base_dir() / "workspace"


def _fail_no_run(console: Console, *, requested: str | None) -> NoReturn:
    base = runs_base_dir()
    available = (
        sorted(
            (child.name for child in base.iterdir() if run_record_path(child).is_file()),
            reverse=True,
        )
        if base.is_dir()
        else []
    )

    if requested:
        console.print(f"[bold red]No run named '{requested}' under ./{RUNS_DIR_NAME}.[/]")
    else:
        console.print(f"[bold red]No runs found under ./{RUNS_DIR_NAME}.[/]")

    if available:
        console.print("Available runs:")
        for name in available[:20]:
            console.print(f"  [cyan]{name}[/]")
    raise SystemExit(1)


__all__ = ["run_view"]
