"""Agent wakeup behavior for provider outages."""

from __future__ import annotations

import asyncio

import pytest

from strix.core.agents import AgentCoordinator
from strix.core.execution import _wait_for_resume


class RecoveringPool:
    def __init__(self) -> None:
        self.ready = asyncio.Event()

    async def wait_until_available(self) -> None:
        await self.ready.wait()


@pytest.mark.asyncio
async def test_provider_waiting_agent_wakes_when_a_route_recovers() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.attach_runtime("root", resumable=True)
    await coordinator.park_waiting("root", wait_kind="provider")
    pool = RecoveringPool()
    waiter = asyncio.create_task(
        _wait_for_resume(
            coordinator,
            "root",
            context={"route_pool": pool},
            timeout=None,
        )
    )

    await asyncio.sleep(0)
    pool.ready.set()

    assert await asyncio.wait_for(waiter, 1) == (False, True)


@pytest.mark.asyncio
async def test_real_message_wins_provider_recovery_race() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None)
    await coordinator.attach_runtime("root", resumable=True)
    await coordinator.park_waiting("root", wait_kind="provider")
    pool = RecoveringPool()
    waiter = asyncio.create_task(
        _wait_for_resume(
            coordinator,
            "root",
            context={"route_pool": pool},
            timeout=None,
        )
    )

    await coordinator.send(
        "root",
        {"from": "user", "type": "instruction", "content": "continue"},
    )

    assert await asyncio.wait_for(waiter, 1) == (True, False)
