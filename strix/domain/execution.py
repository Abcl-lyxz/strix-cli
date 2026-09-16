"""Explicit execution state for one supervised agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from strix.domain.recovery import TurnRecoveryState


class ExecutionPhase(StrEnum):
    PREPARING = "preparing"
    RUNNING = "running"
    RECOVERING = "recovering"
    CHECKPOINTED = "checkpointed"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class ExecutionState:
    """Runtime-owned state machine; UI and persistence observe its transitions."""

    agent_id: str
    recovery: TurnRecoveryState
    phase: ExecutionPhase = ExecutionPhase.PREPARING
    attempt: int = 0
    turn_id: str | None = None
    tool_output_committed: bool = False
    transitions: list[ExecutionPhase] = field(default_factory=list)

    def transition(self, phase: ExecutionPhase) -> None:
        if phase != self.phase:
            self.phase = phase
            self.transitions.append(phase)

    def begin_attempt(self, turn_id: str) -> int:
        self.attempt += 1
        self.turn_id = turn_id
        self.tool_output_committed = False
        self.transition(ExecutionPhase.RUNNING)
        return self.attempt

    def checkpoint(self, now: float, *, tool_completed: bool) -> None:
        self.tool_output_committed = self.tool_output_committed or tool_completed
        self.recovery.reset_after_checkpoint(now)
        self.transition(ExecutionPhase.CHECKPOINTED)
