"""Standalone Windows installer: stdlib only, copied outside the tool environment."""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast


def wait_for_parent(pid: int) -> None:
    if sys.platform == "win32":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.WaitForSingleObject.restype = ctypes.c_uint32
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        handle = kernel.OpenProcess(0x00100000, 0, pid)
        if not handle:
            if ctypes.get_last_error() == 87:  # The parent already exited.
                return
            raise OSError("Cannot wait for the Strix process to exit")
        try:
            if kernel.WaitForSingleObject(handle, 60_000) != 0:
                raise TimeoutError("Strix did not exit; installation was not started")
        finally:
            kernel.CloseHandle(handle)
        # Allow the console-script launcher to exit after its Python child.
        time.sleep(0.3)


def write_status(path: Path, state: dict[str, Any]) -> None:
    # This worker cannot import Strix while replacing that installation.
    temporary = path.with_suffix(f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    temporary.replace(path)


def _installed_python(data: dict[str, Any]) -> Path:
    method = str(data.get("method") or "")
    raw_command = data.get("command")
    command = cast("list[object]", raw_command) if isinstance(raw_command, list) else []
    executable = str(command[0]) if command else method
    scripts = "Scripts" if sys.platform == "win32" else "bin"
    if Path(executable).name.lower().startswith("uv"):
        located = subprocess.run(  # noqa: S603
            [executable, "tool", "dir"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if located.returncode:
            raise RuntimeError("Could not locate the updated uv tool environment")
        return (
            Path(located.stdout.strip())
            / "strix-agent"
            / scripts
            / ("python.exe" if sys.platform == "win32" else "python")
        )
    if Path(executable).name.lower().startswith("pipx"):
        located = subprocess.run(  # noqa: S603
            [executable, "environment", "--value", "PIPX_LOCAL_VENVS"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if located.returncode:
            raise RuntimeError("Could not locate the updated pipx environment")
        return (
            Path(located.stdout.strip())
            / "strix-agent"
            / scripts
            / ("python.exe" if sys.platform == "win32" else "python")
        )
    return Path(executable)


def smoke_test(data: dict[str, Any]) -> None:
    """Verify the installed distribution and the dependency that exposed the race."""
    python = _installed_python(data)
    expected = str(data["version"])
    code = (
        "import importlib.metadata as m; import rich._extension; "
        f"assert m.version('strix-agent') == {expected!r}"
    )
    result = subprocess.run(  # noqa: S603
        [str(python), "-I", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-1_000:]
        raise RuntimeError(f"Installed Strix failed its import check: {detail}")


def install(payload: Path) -> int:
    data = json.loads(payload.read_text(encoding="utf-8"))
    wheel, status = Path(data["wheel"]), Path(data["status"])
    try:
        wait_for_parent(data["parent_pid"])
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != data["sha256"]:
            raise RuntimeError("The staged wheel changed; installation was not started")  # noqa: TRY301
        active = {
            "status": "installing",
            "version": data["version"],
            "started_at": data.get("started_at", time.time()),
        }
        write_status(status, active)
        result = subprocess.run(data["command"], check=False)  # noqa: S603
        if result.returncode:
            raise RuntimeError(f"Package installer exited with code {result.returncode}")  # noqa: TRY301
        write_status(status, {**active, "status": "verifying"})
        smoke_test(data)
        write_status(status, {"status": "complete", "version": data["version"]})
        sys.stdout.write(f"Strix {data['version']} installed. Run strix --version to confirm.\n")
    except Exception as exc:  # noqa: BLE001
        write_status(status, {"status": "failed", "version": data["version"], "error": str(exc)})
        sys.stderr.write(f"Update failed: {exc}\n")
        return 1
    else:
        return 0
    finally:
        with contextlib.suppress(OSError):
            wheel.unlink(missing_ok=True)
            payload.unlink(missing_ok=True)
            (payload.parent / "install.py").unlink(missing_ok=True)
            payload.parent.rmdir()


if __name__ == "__main__":
    raise SystemExit(install(Path(sys.argv[1])))
