from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.config.settings import DEFAULT_MAX_AGENTS
from strix.interface.cli_args import parse_arguments


def test_cli_defaults_to_bounded_agent_graph(monkeypatch: Any) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--target", "example.com"])

    assert parse_arguments().max_agents == DEFAULT_MAX_AGENTS


def test_cli_accepts_agent_limit(monkeypatch: Any) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--target", "example.com", "--max-agents", "4"])

    assert parse_arguments().max_agents == 4


def test_cli_rejects_limit_that_leaves_no_specialist(monkeypatch: Any) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--target", "example.com", "--max-agents", "1"])

    with pytest.raises(SystemExit):
        parse_arguments()
