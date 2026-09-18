"""Minimal Strix v2 command-line boundary.

Interactive configuration and scan execution live in the TUI. The parser
rejects every former scan/setup flag before runtime work can start, so a
partially parsed legacy command can never launch a scan.
"""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version

from strix.config.app_config import get_config_service
from strix.domain.app_state import LaunchState, ScanDraft


_MOVED_TO_TUI = (
    "Strix v2 moved scan targets, providers, models, routes, authentication, updates, "
    "notifications, resume, and all scan options into the TUI. Run `strix` and use "
    "/help. Only `strix --help`, `strix --version`, and `strix doctor` remain outside it."
)


def get_version() -> str:
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        return "2.0.2"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strix",
        description="Strix v2 autonomous security testing (interactive TUI)",
        epilog=(
            "Run `strix` to open the control plane. Inside the TUI use /connect for "
            "credentials, /models for eligible models, /targets for scope, and /start.\n\n"
            "Diagnostics: strix doctor [--network]"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"strix {get_version()}")
    return parser


def parse_arguments(argv: list[str] | None = None) -> LaunchState:
    parser = _parser()
    values = list(argv) if argv is not None else None
    _parsed, unknown = parser.parse_known_args(values)
    if unknown:
        parser.error(_MOVED_TO_TUI + f"\nUnsupported legacy argument: {unknown[0]}")
    config = get_config_service().load()
    return LaunchState(draft=ScanDraft.from_config(config))


__all__ = ["LaunchState", "get_version", "parse_arguments"]
