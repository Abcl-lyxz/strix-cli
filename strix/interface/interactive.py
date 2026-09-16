"""Launch the interactive terminal interface."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import argparse

    from strix.report.state import ReportState


logger = logging.getLogger(__name__)


class InteractiveSetupUnavailableError(RuntimeError):
    """Raised when the interactive TUI cannot be launched."""


async def run_tui(args: argparse.Namespace) -> ReportState | None:
    """Run the Bubble Tea TUI."""
    from strix.interface.tui.runtime import (
        GoTuiPreActivationError,
        run_go_tui,
    )

    try:
        return await run_go_tui(args)
    except GoTuiPreActivationError as exc:
        raise InteractiveSetupUnavailableError(
            f"The interactive interface could not start: {exc}"
        ) from exc


__all__ = [
    "InteractiveSetupUnavailableError",
    "run_tui",
]
