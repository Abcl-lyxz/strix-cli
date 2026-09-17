from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from strix.config.app_config import AppConfig
from strix.interface import cli_args


interface_main = importlib.import_module("strix.interface.main")


@pytest.fixture(autouse=True)
def _isolated_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_args,
        "get_config_service",
        lambda: SimpleNamespace(load=AppConfig),
    )


@pytest.mark.parametrize("argument", ["--version", "--help"])
def test_utility_flags_exit_before_tui(monkeypatch: pytest.MonkeyPatch, argument: str) -> None:
    monkeypatch.setattr(interface_main.sys, "argv", ["strix", argument])
    monkeypatch.setattr(
        interface_main,
        "run_tui",
        lambda _args: pytest.fail("utility flag entered the TUI"),
    )
    with pytest.raises(SystemExit, match="0"):
        interface_main.main()


def test_plain_launch_enters_tui_without_docker_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def run_tui(_args: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(interface_main.sys, "argv", ["strix"])
    monkeypatch.setattr(interface_main, "start_background_check", lambda: None)
    monkeypatch.setattr(interface_main, "run_tui", run_tui)
    interface_main.main()
    assert called is True


def test_legacy_update_flag_fails_before_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(interface_main.sys, "argv", ["strix", "--update"])
    monkeypatch.setattr(
        interface_main,
        "run_tui",
        lambda _args: pytest.fail("legacy update flag entered the TUI"),
    )
    with pytest.raises(SystemExit, match="2"):
        interface_main.main()
