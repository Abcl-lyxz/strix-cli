from __future__ import annotations

from typing import Any

import pytest

from strix.application.commands import Command, CommandRegistry


@pytest.mark.asyncio
async def test_exact_command_wins_over_namespace_without_mutating_payload() -> None:
    registry = CommandRegistry()

    async def exact(payload: dict[str, Any]) -> dict[str, Any]:
        return {"handler": "exact", "payload": payload}

    async def namespace(command: Command) -> dict[str, Any]:
        return {"handler": "namespace", "command": command.name}

    registry.register("scan.retry", exact)
    registry.register_namespace("scan", namespace)
    payload = {"agent_id": "root"}
    result = await registry.dispatch(Command("scan.retry", payload))
    assert result == {"handler": "exact", "payload": payload}
    assert payload == {"agent_id": "root"}


@pytest.mark.asyncio
async def test_namespace_handler_receives_typed_command() -> None:
    registry = CommandRegistry()

    async def handler(command: Command) -> dict[str, Any]:
        return {"name": command.name, "namespace": command.namespace}

    registry.register_namespace("providers", handler)
    result = await registry.dispatch(Command("providers.discover", {}))
    assert result == {"name": "providers.discover", "namespace": "providers"}


@pytest.mark.asyncio
async def test_unknown_command_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown command"):
        await CommandRegistry().dispatch(Command("unknown.command", {}))
