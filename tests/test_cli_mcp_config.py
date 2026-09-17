"""The v2 CLI must never mutate MCP selection from legacy flags."""

from __future__ import annotations

import os
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
        ["--mcp-config", "servers.json"],
        ["--mcp-server", "a"],
        ["--mcp-exclude", "b"],
    ],
)
def test_mcp_flags_fail_before_mutating_environment(
    arguments: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("STRIX_MCP_CONFIG", raising=False)
    monkeypatch.delenv("STRIX_MCP_ONLY", raising=False)
    monkeypatch.delenv("STRIX_MCP_EXCLUDE", raising=False)

    with pytest.raises(SystemExit, match="2"):
        cli_args.parse_arguments(arguments)

    assert "STRIX_MCP_CONFIG" not in os.environ
    assert "STRIX_MCP_ONLY" not in os.environ
    assert "STRIX_MCP_EXCLUDE" not in os.environ
