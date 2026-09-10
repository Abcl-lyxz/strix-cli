"""Locate the Docker CLI, including fresh Docker Desktop installations."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import MutableMapping


def _windows_docker_candidates(environ: MutableMapping[str, str]) -> list[Path]:
    """Return Docker Desktop CLI locations in per-user-first order."""
    candidates: list[Path] = []
    local_app_data = environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Programs/DockerDesktop/resources/bin/docker.exe")
    for variable in ("ProgramFiles", "ProgramW6432"):
        root = environ.get(variable)
        if root:
            candidates.append(Path(root) / "Docker/Docker/resources/bin/docker.exe")
    return candidates


def _prepend_path(directory: Path, environ: MutableMapping[str, str]) -> None:
    current = environ.get("PATH", "")
    normalized = os.path.normcase(str(directory.resolve()))
    entries = [entry for entry in current.split(os.pathsep) if entry]
    if any(os.path.normcase(str(Path(entry).resolve())) == normalized for entry in entries):
        return
    environ["PATH"] = str(directory) + (os.pathsep + current if current else "")


def find_docker_cli(environ: MutableMapping[str, str] | None = None) -> str | None:
    """Find Docker and repair a stale Windows process PATH when possible.

    Docker Desktop updates the persistent user PATH during installation, but an
    already-running terminal host can keep its previous environment. Discovering
    the standard install location here makes Strix work immediately and also
    exposes Docker's sibling credential helpers to child processes.
    """
    target_env = os.environ if environ is None else environ
    executable = shutil.which("docker", path=target_env.get("PATH"))
    if executable is not None:
        return executable
    if sys.platform != "win32":
        return None
    for candidate in _windows_docker_candidates(target_env):
        if candidate.is_file():
            _prepend_path(candidate.parent, target_env)
            return str(candidate)
    return None
