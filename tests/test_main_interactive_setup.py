from __future__ import annotations

import argparse
import importlib
from types import SimpleNamespace

import pytest

from strix.interface import cli_args


interface_main = importlib.import_module("strix.interface.main")


def test_missing_model_routes_direct_target_through_interactive_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = argparse.Namespace(needs_setup=False)
    monkeypatch.setattr(
        interface_main,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model=None)),
    )

    interface_main._ensure_interactive_setup_for_model(args)

    assert args.needs_setup is True


def test_configured_model_preserves_direct_interactive_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = argparse.Namespace(needs_setup=False)
    monkeypatch.setattr(
        interface_main,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model="openai/gpt-5.4")),
    )

    interface_main._ensure_interactive_setup_for_model(args)

    assert args.needs_setup is False


def test_saved_route_preserves_direct_interactive_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = argparse.Namespace(needs_setup=False)
    settings = SimpleNamespace(llm=SimpleNamespace(model=None))
    monkeypatch.setattr(interface_main, "load_settings", lambda: settings)
    monkeypatch.setattr(
        interface_main,
        "load_routes",
        lambda _settings: [SimpleNamespace(model="openai/gpt-5.4")],
    )

    interface_main._ensure_interactive_setup_for_model(args)

    assert args.needs_setup is False


@pytest.mark.parametrize("argument", ["--version", "--help", "--update"])
def test_early_cli_commands_exit_without_scan_import_threads(
    monkeypatch: pytest.MonkeyPatch, argument: str
) -> None:
    def unexpected_warmup() -> None:
        pytest.fail("An early command must not leave scan imports running at shutdown")

    monkeypatch.setattr(interface_main.sys, "argv", ["strix", argument])
    monkeypatch.setattr(interface_main, "start_import_warmup", unexpected_warmup)
    monkeypatch.setattr(cli_args, "self_update", lambda: True)
    with pytest.raises(SystemExit) as result:
        interface_main.main()
    assert result.value.code == 0


def test_startup_update_exits_before_starting_scan_import_threads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_warmup() -> None:
        pytest.fail("An accepted update must exit without loading scan dependencies")

    monkeypatch.setattr(interface_main.sys, "argv", ["strix"])
    monkeypatch.setattr(
        interface_main, "parse_arguments", lambda: argparse.Namespace(non_interactive=False)
    )
    monkeypatch.setattr(interface_main, "start_background_check", lambda: None)
    monkeypatch.setattr(interface_main, "prompt_update_if_available", lambda _console: True)
    monkeypatch.setattr(interface_main, "is_binary_install", lambda: False)
    monkeypatch.setattr(interface_main, "start_import_warmup", unexpected_warmup)
    with pytest.raises(SystemExit) as result:
        interface_main.main()
    assert result.value.code == 0


def test_docker_unavailable_exits_without_an_unhandled_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_started = False

    async def run_tui(_args: argparse.Namespace) -> None:
        nonlocal runtime_started
        runtime_started = True

    monkeypatch.setattr(interface_main.sys, "argv", ["strix"])
    monkeypatch.setattr(
        interface_main,
        "parse_arguments",
        lambda: argparse.Namespace(non_interactive=False),
    )
    monkeypatch.setattr(interface_main, "start_background_check", lambda: None)
    monkeypatch.setattr(interface_main, "prompt_update_if_available", lambda _console: False)
    monkeypatch.setattr(interface_main, "start_import_warmup", lambda: None)
    monkeypatch.setattr(interface_main, "check_docker_installed", lambda: None)
    monkeypatch.setattr(
        interface_main,
        "pull_docker_image",
        lambda: (_ for _ in ()).throw(RuntimeError("Docker not available")),
    )
    monkeypatch.setattr(interface_main, "run_tui", run_tui)

    with pytest.raises(SystemExit) as result:
        interface_main.main()

    assert result.value.code == 1
    assert runtime_started is False
