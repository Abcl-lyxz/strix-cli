"""Serialized, atomic local writes with bounded Windows sharing retries."""

from __future__ import annotations

import contextlib
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable


_locks: dict[str, threading.RLock] = {}
_guard = threading.Lock()
_failures: dict[Path, str] = {}


def path_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve()))
    with _guard:
        return _locks.setdefault(key, threading.RLock())


def atomic_write_text(
    path: Path, payload: str | Callable[[], str], *, mode: int | None = None
) -> None:
    """Build snapshots under the destination lock; never publish stale captures."""
    with path_lock(path):
        try:
            _write(path, payload, mode)
        except OSError as exc:
            with _guard:
                _failures[path.resolve()] = str(exc)
            from strix.notifications import notify  # noqa: PLC0415 - notify also uses persistence

            notify(
                "storage.failed",
                title="Local state could not be saved",
                detail=str(exc),
                severity="error",
                dedupe_key=f"storage:{path.resolve()}",
            )
            raise
        else:
            with _guard:
                _failures.pop(path.resolve(), None)


def storage_failures(root: Path) -> dict[str, str]:
    root = root.resolve()
    with _guard:
        return {str(path): error for path, error in _failures.items() if path.is_relative_to(root)}


def _write(path: Path, payload: str | Callable[[], str], mode: int | None) -> None:
    text = payload() if callable(payload) else payload
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            temporary.chmod(mode)
        for attempt in range(6):
            try:
                temporary.replace(path)
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(min(0.025 * 2**attempt, 0.4))
            else:
                return
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
