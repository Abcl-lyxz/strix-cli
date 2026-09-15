"""CLI entry point with a stdlib-only Windows update gate.

The package updater runs after the previous Strix process exits.  A new CLI
process can otherwise start while uv or pipx is still replacing site-packages
and observe a partially installed dependency.  Keep this module free of
third-party imports until the handoff status reaches a terminal state.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from collections.abc import Callable


_UPDATE_STATUS = Path.home() / ".strix" / "update-install.json"
_ACTIVE_UPDATE_STATES = frozenset({"pending", "installing", "verifying"})
_UPDATE_STALE_AFTER = 1_200.0


def _read_update_status(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return {}
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _wait_for_package_update(
    status_path: Path = _UPDATE_STATUS,
    *,
    timeout: float = 1_200.0,
    poll_interval: float = 0.2,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Wait before importing dependencies while a verified update is active."""
    deadline = time.monotonic() + max(0.0, timeout)
    announced = False
    while True:
        state = _read_update_status(status_path)
        status = state.get("status")
        started_at = state.get("started_at")
        fresh = (
            isinstance(started_at, int | float) and time.time() - started_at < _UPDATE_STALE_AFTER
        )
        if status not in _ACTIVE_UPDATE_STATES or not fresh:
            if status == "failed":
                sys.stderr.write(
                    f"The previous Strix update failed; see {status_path.with_suffix('.log')}\n"
                )
            return
        if not announced:
            sys.stdout.write(
                "A verified Strix update is still installing; waiting for it to finish...\n"
            )
            announced = True
        if time.monotonic() >= deadline:
            sys.stderr.write(f"Update is still active; inspect {status_path}\n")
            raise SystemExit(1)
        sleep(max(0.01, poll_interval))


_wait_for_package_update()

from .main import main  # noqa: E402


__all__ = ["main"]
