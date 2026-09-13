"""Shared test fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix import notifications as notification_module
from strix.config import loader as config_loader
from strix.config import routes as route_config
from strix.security import SecretStore
from strix.security import secrets as secret_module
from strix.tools.mcp import loader as mcp_loader


if TYPE_CHECKING:
    from pathlib import Path


class _MemorySecretBackend:
    name = "test keychain"
    available = True

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, ref: str) -> str | None:
        return self.values.get(ref)

    def set(self, ref: str, value: str) -> None:
        self.values[ref] = value

    def delete(self, ref: str) -> bool:
        return self.values.pop(ref, None) is not None


@pytest.fixture(autouse=True)
def _isolate_global_strix_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep tests away from the developer's routes and notification inbox."""
    monkeypatch.setattr(config_loader, "_override", tmp_path / "cli-config.json")
    monkeypatch.setattr(config_loader, "_cached", None)
    monkeypatch.setattr(config_loader, "_session_fields", {})
    monkeypatch.setattr(route_config, "_session_routes", {})
    monkeypatch.setattr(route_config, "_session_selected", None)
    monkeypatch.setattr(route_config, "_session_revision", 0)
    monkeypatch.setattr(mcp_loader, "_session_configs", {})
    monkeypatch.setattr(secret_module, "_known_values", set())
    monkeypatch.setattr(notification_module, "_DEFAULT_PATH", tmp_path / "state.db")
    monkeypatch.setattr(notification_module, "_default_service", None)
    for name in (
        "STRIX_ROUTES_FILE",
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "OLLAMA_API_BASE",
        "LLM_EXTRA_HEADERS",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolate_secret_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let tests read, write, or delete credentials in the user's keychain."""
    monkeypatch.setattr(secret_module, "_default_store", SecretStore(_MemorySecretBackend()))


@pytest.fixture(autouse=True)
def _isolate_mcp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep the whole suite from reading the developer's real MCP config.

    ``run_strix_scan`` connects the MCP servers listed in
    ``~/.strix/mcp-servers.json`` and threads an inventory of them into the
    prompt context. Without isolation, any test that drives the runner on a
    machine that has a real config would do real network I/O and see MCP
    connections it never asked for. Point the loader at a path that does not
    exist so it resolves to "no connections", and clear the per-run selection
    env vars. Tests that exercise the loader itself set their own
    ``STRIX_MCP_CONFIG`` after this runs and so override it.
    """
    missing = tmp_path_factory.mktemp("mcp-isolation") / "no-servers.json"
    monkeypatch.setenv("STRIX_MCP_CONFIG", str(missing))
    monkeypatch.delenv("STRIX_MCP_ONLY", raising=False)
    monkeypatch.delenv("STRIX_MCP_EXCLUDE", raising=False)


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Rich output identical on every developer's machine.

    Many CLI tests force ``isatty()`` to ``True`` to exercise the human-readable
    code path and then assert on the plain text. Rich picks its color system
    from ``TERM``, ``COLORTERM``, and ``FORCE_COLOR``, so on a real terminal
    those assertions would meet ANSI escape codes instead of the words they
    look for. A dumb terminal renders the same text without any styling.
    """
    monkeypatch.setenv("TERM", "dumb")
    for name in ("COLORTERM", "FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE"):
        monkeypatch.delenv(name, raising=False)
