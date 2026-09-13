"""OS-owned scan leases and heartbeat metadata, released even on process death."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import os
import sys
import time
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from strix.core.paths import run_dir_for
from strix.utils.atomic import atomic_write_text


if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


if TYPE_CHECKING:
    from pathlib import Path


class RunLease:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.handle: Any = None

    def acquire(self) -> None:
        path = self.run_dir / ".state" / "owner.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+b")
        if path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if sys.platform == "win32":
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise RuntimeError("This scan is already active in another process") from None
        self.handle = handle

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None


def run_is_active(run_dir: Path) -> bool:
    if not (run_dir / ".state" / "owner.lock").exists():
        return False
    lease = RunLease(run_dir)
    try:
        lease.acquire()
    except (OSError, RuntimeError):
        return True
    finally:
        lease.close()
    return False


def owned_run(function: Any) -> Any:
    @functools.wraps(function)
    async def run(*args: Any, **kwargs: Any) -> Any:
        config: dict[str, Any] = kwargs.get("scan_config") or {}
        scan_id = str(kwargs.get("scan_id") or config.get("scan_id") or f"scan-{uuid4().hex[:8]}")
        kwargs["scan_id"] = scan_id
        directory = run_dir_for(scan_id)
        lease = kwargs.pop("run_lease", None)
        if lease is None:
            lease = RunLease(directory)
            lease.acquire()

        async def beat() -> None:
            while True:
                await asyncio.to_thread(
                    atomic_write_text,
                    directory / ".state" / "owner.json",
                    json.dumps({"pid": os.getpid(), "heartbeat": time.time()}),
                )
                await asyncio.sleep(5)

        task = asyncio.create_task(beat())
        try:
            return await function(*args, **kwargs)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, OSError):
                await task
            lease.close()

    return run


def owned_cli(function: Any) -> Any:
    @functools.wraps(function)
    async def run(args: Any) -> Any:
        lease = RunLease(run_dir_for(args.run_name))
        lease.acquire()
        args.run_lease = lease
        try:
            return await function(args)
        finally:
            lease.close()

    return run
