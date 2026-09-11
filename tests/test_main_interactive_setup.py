from __future__ import annotations

import argparse
import importlib
from types import SimpleNamespace
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import pytest


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
