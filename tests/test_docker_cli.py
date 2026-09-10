from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from strix.interface import docker_cli


if TYPE_CHECKING:
    from pathlib import Path


def test_existing_docker_on_path_is_returned_without_changes(monkeypatch: Any) -> None:
    environ = {"PATH": "existing-path"}
    monkeypatch.setattr(docker_cli.shutil, "which", lambda *_args, **_kwargs: "docker-found")

    assert docker_cli.find_docker_cli(environ) == "docker-found"
    assert environ["PATH"] == "existing-path"


def test_windows_desktop_install_repairs_stale_process_path(
    tmp_path: Path, monkeypatch: Any
) -> None:
    docker = tmp_path / "Programs/DockerDesktop/resources/bin/docker.exe"
    docker.parent.mkdir(parents=True)
    docker.touch()
    environ = {"LOCALAPPDATA": str(tmp_path), "PATH": "existing-path"}
    monkeypatch.setattr(docker_cli.sys, "platform", "win32")
    monkeypatch.setattr(docker_cli.shutil, "which", lambda *_args, **_kwargs: None)

    assert docker_cli.find_docker_cli(environ) == str(docker)
    assert environ["PATH"].split(os.pathsep)[0] == str(docker.parent)


def test_missing_non_windows_docker_does_not_change_path(monkeypatch: Any) -> None:
    environ = {"PATH": "existing-path"}
    monkeypatch.setattr(docker_cli.sys, "platform", "linux")
    monkeypatch.setattr(docker_cli.shutil, "which", lambda *_args, **_kwargs: None)

    assert docker_cli.find_docker_cli(environ) is None
    assert environ["PATH"] == "existing-path"
