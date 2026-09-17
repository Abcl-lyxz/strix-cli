"""Pure state and decisions for one logical model turn's recovery budget."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal


if TYPE_CHECKING:
    from strix.domain.failures import FailureKind


RecoveryAction = Literal[
    "strip_images",
    "compact",
    "repair_history",
    "wait_for_route",
    "retry_model",
    "restart_agent",
    "park",
    "fail",
]


@dataclass(frozen=True, slots=True)
class RecoveryLimits:
    """Budgets shared by every recovery mechanism for a logical turn."""

    total_attempts: int = 8
    image_strips: int = 3
    compactions: int = 2
    history_repairs: int = 2
    route_resumptions: int = 1
    model_retries: int = 2
    crash_restarts: int = 2
    max_elapsed_seconds: float = 120.0


@dataclass(slots=True)
class TurnRecoveryState:
    """Mutable counters owned by a single logical turn, never by the process."""

    started_at: float
    attempts: int = 0
    image_strips: int = 0
    compactions: int = 0
    history_repairs: int = 0
    route_resumptions: int = 0
    model_retries: int = 0
    crash_restarts: int = 0
    successful_checkpoints: int = 0
    last_failure: FailureKind | None = None
    history: list[RecoveryAction] = field(default_factory=list)

    def reset_after_checkpoint(self, now: float) -> None:
        """A committed model/tool boundary starts a fresh logical turn."""

        self.started_at = now
        self.attempts = 0
        self.image_strips = 0
        self.compactions = 0
        self.history_repairs = 0
        self.route_resumptions = 0
        self.model_retries = 0
        self.crash_restarts = 0
        self.successful_checkpoints += 1
        self.last_failure = None
        self.history.clear()

    def record(self, action: RecoveryAction, failure: FailureKind) -> None:
        self.attempts += 1
        self.last_failure = failure
        self.history.append(action)
        if action == "strip_images":
            self.image_strips += 1
        elif action == "compact":
            self.compactions += 1
        elif action == "repair_history":
            self.history_repairs += 1
        elif action == "wait_for_route":
            self.route_resumptions += 1
        elif action == "retry_model":
            self.model_retries += 1
        elif action == "restart_agent":
            self.crash_restarts += 1


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    action: RecoveryAction
    reason: str
    failure: FailureKind
    delay_seconds: float = 0.0
    terminal_status: Literal["failed", "crashed", "stopped"] | None = None
