from __future__ import annotations

from types import SimpleNamespace

import pytest

from strix.config.app_config import AppConfig
from strix.config.settings import DEFAULT_MAX_AGENTS
from strix.interface import cli_args


@pytest.fixture(autouse=True)
def _isolated_v3_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_args,
        "get_config_service",
        lambda: SimpleNamespace(load=AppConfig),
    )


def test_cli_opens_tui_with_configured_scan_defaults() -> None:
    assert cli_args.parse_arguments([]).max_agents == DEFAULT_MAX_AGENTS


@pytest.mark.parametrize(
    "arguments",
    [
        ["--target", "example.com"],
        ["--max-agents", "4"],
        ["-n", "-t", "example.com"],
        ["routes", "list"],
    ],
)
def test_cli_rejects_every_legacy_scan_or_setup_argument(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli_args.parse_arguments(arguments)
    assert "moved" in capsys.readouterr().err
