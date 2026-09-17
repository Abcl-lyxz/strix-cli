"""Targets and resume are TUI-owned in Strix v2."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from strix.config.app_config import AppConfig
from strix.interface import cli_args


@pytest.fixture(autouse=True)
def _isolated_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_args,
        "get_config_service",
        lambda: SimpleNamespace(load=AppConfig),
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["--target-list", "targets.txt"],
        ["-t", "https://example.com"],
        ["--resume", "pentest_abcd"],
    ],
)
def test_target_and_resume_flags_fail_fast(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli_args.parse_arguments(arguments)
    assert "moved" in capsys.readouterr().err
