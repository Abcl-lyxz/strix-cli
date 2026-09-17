#!/usr/bin/env python3
"""Strix v2 process entry point.

The executable is deliberately a small boundary: diagnostics may run outside
the application, while every scan and configuration workflow enters the TUI.
"""

from __future__ import annotations

import asyncio
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.interface.cli_args import parse_arguments
from strix.interface.interactive import InteractiveSetupUnavailableError, run_tui
from strix.interface.update_check import start_background_check
from strix.telemetry import report_error
from strix.telemetry.logging import configure_dependency_logging


def _print_error_panel(title: str, message: str) -> None:
    error_text = Text()
    error_text.append(title, style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(message, style="white")
    Console().print(
        Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
    )


def main() -> None:
    configure_dependency_logging()
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # Doctor is intentionally the only non-TUI subcommand in v2.
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        from strix.interface.doctor import run_doctor

        raise SystemExit(run_doctor(sys.argv[2:]))

    args = parse_arguments()
    start_background_check()
    try:
        asyncio.run(run_tui(args))
    except InteractiveSetupUnavailableError as exc:
        report_error("interactive_setup_unavailable", exc)
        _print_error_panel("INTERACTIVE SETUP UNAVAILABLE", str(exc))
        raise SystemExit(1) from exc
    except KeyboardInterrupt:
        return
    except Exception as exc:
        report_error("unhandled_exception", exc)
        raise


if __name__ == "__main__":
    main()
