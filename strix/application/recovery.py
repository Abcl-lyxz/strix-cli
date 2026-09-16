"""Central policy for every retry/recovery decision in one logical turn."""

from __future__ import annotations

from dataclasses import dataclass

from strix.domain.failures import NON_RETRYABLE_FAILURES, FailureKind
from strix.domain.recovery import RecoveryDecision, RecoveryLimits, TurnRecoveryState


@dataclass(frozen=True, slots=True)
class RecoverySituation:
    failure: FailureKind
    safe_to_retry: bool
    interactive: bool
    has_route_pool: bool
    can_strip_images: bool = False
    can_compact: bool = False
    elapsed_seconds: float = 0.0
    retry_delay: float = 0.0


class RecoveryPolicy:
    """Return one action while enforcing a shared bounded attempt budget."""

    def __init__(self, limits: RecoveryLimits | None = None) -> None:
        self.limits = limits or RecoveryLimits()

    def decide(  # noqa: PLR0911, PLR0912 - exhaustive recovery decision table
        self,
        state: TurnRecoveryState,
        situation: RecoverySituation,
    ) -> RecoveryDecision:
        failure = situation.failure
        if failure in NON_RETRYABLE_FAILURES:
            return RecoveryDecision("fail", f"{failure} failures are not retryable", failure)
        if state.attempts >= self.limits.total_attempts:
            return RecoveryDecision(
                "fail",
                "logical-turn recovery budget exhausted",
                failure,
                terminal_status="failed",
            )
        if situation.elapsed_seconds >= self.limits.max_elapsed_seconds:
            return RecoveryDecision(
                "fail",
                "logical-turn recovery time budget exhausted",
                failure,
                terminal_status="failed",
            )
        if (
            situation.safe_to_retry
            and situation.can_strip_images
            and state.image_strips < self.limits.image_strips
        ):
            return RecoveryDecision("strip_images", "provider rejected retained images", failure)
        if failure == "context" and situation.safe_to_retry and situation.can_compact:
            if state.compactions < self.limits.compactions:
                return RecoveryDecision("compact", "context window overflow", failure)
            return RecoveryDecision("fail", "context compaction budget exhausted", failure)
        if failure == "malformed":
            if situation.safe_to_retry and state.history_repairs < self.limits.history_repairs:
                return RecoveryDecision("repair_history", "malformed provider history", failure)
            return RecoveryDecision("fail", "history repair is unsafe or exhausted", failure)
        if failure == "transient" and situation.safe_to_retry:
            if situation.has_route_pool:
                if state.route_resumptions < self.limits.route_resumptions:
                    return RecoveryDecision(
                        "wait_for_route",
                        "all eligible routes are temporarily unavailable",
                        failure,
                    )
                return RecoveryDecision("park", "route recovery budget exhausted", failure)
            if state.model_retries < self.limits.model_retries:
                return RecoveryDecision(
                    "retry_model",
                    "transient model failure",
                    failure,
                    delay_seconds=max(0.0, situation.retry_delay),
                )
        if (
            failure == "fatal"
            and situation.safe_to_retry
            and state.crash_restarts < self.limits.crash_restarts
        ):
            return RecoveryDecision(
                "restart_agent",
                "unexpected agent failure",
                failure,
                delay_seconds=max(0.0, situation.retry_delay),
            )
        return RecoveryDecision(
            "fail",
            "failure is not recoverable without replay risk",
            failure,
            terminal_status="crashed" if failure == "fatal" else "failed",
        )
