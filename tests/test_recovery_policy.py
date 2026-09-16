from __future__ import annotations

from strix.application.recovery import RecoveryPolicy, RecoverySituation
from strix.domain.recovery import RecoveryLimits, TurnRecoveryState


def _state(**values: object) -> TurnRecoveryState:
    state = TurnRecoveryState(started_at=10.0)
    for name, value in values.items():
        setattr(state, name, value)
    return state


def test_nonretryable_failures_never_consume_recovery_path() -> None:
    decision = RecoveryPolicy().decide(
        _state(),
        RecoverySituation(
            failure="authentication",
            safe_to_retry=True,
            interactive=True,
            has_route_pool=True,
        ),
    )
    assert decision.action == "fail"


def test_one_attempt_budget_bounds_all_mechanisms() -> None:
    policy = RecoveryPolicy(RecoveryLimits(total_attempts=2))
    state = _state(attempts=2)
    decision = policy.decide(
        state,
        RecoverySituation(
            failure="transient",
            safe_to_retry=True,
            interactive=True,
            has_route_pool=True,
        ),
    )
    assert decision.action == "fail"
    assert "budget exhausted" in decision.reason


def test_elapsed_budget_prevents_route_parking_loop() -> None:
    policy = RecoveryPolicy(RecoveryLimits(max_elapsed_seconds=30))
    decision = policy.decide(
        _state(),
        RecoverySituation(
            failure="transient",
            safe_to_retry=True,
            interactive=True,
            has_route_pool=True,
            elapsed_seconds=30,
        ),
    )
    assert decision.action == "fail"
    assert "time budget" in decision.reason


def test_checkpoint_resets_logical_turn_budget() -> None:
    state = _state(
        attempts=4,
        compactions=1,
        model_retries=2,
        successful_checkpoints=3,
    )
    state.record("compact", "context")
    state.reset_after_checkpoint(now=42.0)
    assert state.attempts == 0
    assert state.compactions == 0
    assert state.model_retries == 0
    assert state.successful_checkpoints == 4
    assert state.history == []
