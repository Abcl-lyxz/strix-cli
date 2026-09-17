"""Health-aware shared model routing for Strix agents."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import os
import time
from collections import deque
from dataclasses import asdict, dataclass, field, replace
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal, cast

import litellm
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelProvider

from strix.llm.context_budget import context_window, count_tokens
from strix.llm.error_envelope import error_envelope
from strix.notifications import NotificationAction
from strix.resilience import full_jitter_delay, retry_after_seconds
from strix.security import get_secret_store, redact_secrets, register_secret
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

    from agents.agent_output import AgentOutputSchemaBase
    from agents.handoffs import Handoff
    from agents.items import ModelResponse, TResponseInputItem, TResponseStreamEvent
    from agents.models.interface import ModelTracing
    from agents.tool import Tool
    from openai.types.responses.response_prompt_param import ResponsePromptParam

    from strix.domain.routes import RouteConfig
    from strix.ports.notifications import NotificationPublisher


logger = logging.getLogger(__name__)

RouteFailureKind = Literal[
    "transient",
    "authentication",
    "billing",
    "context",
    "policy",
    "incompatible",
    "fatal",
]
TaskKind = Literal["recon", "coding", "long_context", "vision", "general"]


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    """Provider-independent requirements for one logical model turn."""

    agent_role: str = "agent"
    scan_phase: str = "analysis"
    task_kind: TaskKind = "general"
    requires_tools: bool = False
    requires_vision: bool = False
    prefers_reasoning: bool = False
    estimated_input_tokens: int = 1
    estimated_output_tokens: int = 4_096
    budget_remaining_usd: float | None = None


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """A deterministic routing decision suitable for a redacted run artifact."""

    route_id: str
    model: str
    reason: str
    rejected: dict[str, str]
    request: RoutingRequest


_routing_context: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "strix_routing_context", default=None
)


def set_routing_context(**values: Any) -> contextvars.Token[dict[str, Any] | None]:
    """Set logical-turn metadata; callers must reset the returned token."""

    current = dict(_routing_context.get() or {})
    current.update({key: value for key, value in values.items() if value is not None})
    return _routing_context.set(current)


def reset_routing_context(token: contextvars.Token[dict[str, Any] | None]) -> None:
    _routing_context.reset(token)


_QUALITY_RANK = {
    "frontier": 0,
    "strong": 1,
    "standard": 2,
    "economy": 3,
    "unknown": 4,
}


@dataclass(slots=True)
class _UsageEntry:
    timestamp: float
    tokens: int


def _call_history() -> deque[float]:
    return deque()


def _token_history() -> deque[_UsageEntry]:
    return deque()


@dataclass(slots=True)
class RouteState:
    config: RouteConfig
    active: int = 0
    cooldown_until: float = 0.0
    consecutive_failures: int = 0
    blocked_reason: str | None = None
    disabled_for_run: bool = False
    calls: deque[float] = field(default_factory=_call_history)
    usage: deque[_UsageEntry] = field(default_factory=_token_history)
    successful_turns: int = 0
    failed_turns: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    attempted_input_tokens: int = 0
    retry_waste_tokens: int = 0
    last_request_input_tokens: int = 0
    last_reserved_output_tokens: int = 0
    last_progress_at: float | None = None
    latency_ms_ewma: float = 0.0
    effective_concurrency: int = 0
    probe_in_flight: bool = False
    learned_context_window: int | None = None
    last_error: dict[str, object] | None = None

    def __post_init__(self) -> None:
        self.effective_concurrency = self.config.max_concurrency

    def context_capacity(self) -> int:
        configured = self.config.context_window_tokens or context_window(self.config.model)
        return min(configured, self.learned_context_window or configured)

    def circuit_state(self, now: float) -> str:
        if self.blocked_reason or self.disabled_for_run or not self.config.enabled:
            return "open"
        if self.consecutive_failures and self.cooldown_until > now:
            return "open"
        if self.consecutive_failures:
            return "half_open"
        return "closed"

    def available(self, now: float) -> bool:
        return (
            self.config.enabled
            and not self.disabled_for_run
            and self.blocked_reason is None
            and self.cooldown_until <= now
            and self.active < self.effective_concurrency
            and (not self.consecutive_failures or not self.probe_in_flight)
        )


class AllRoutesUnavailableError(RuntimeError):
    """Every configured route is blocked or remained unavailable until timeout."""


class RouteContextOverflowError(RuntimeError):
    """No healthy route has enough context capacity for the pending request."""


def classify_route_failure(exc: BaseException) -> RouteFailureKind:
    from strix.llm.errors import classify_model_failure  # noqa: PLC0415 - avoid config cycle

    kind = classify_model_failure(exc)
    if kind == "malformed":
        return "fatal"  # execution owns history recovery, not the route pool
    return kind


class RoutePool:
    """One shared route-health and concurrency pool for every scan agent."""

    def __init__(
        self,
        routes: list[RouteConfig],
        *,
        wait_timeout: float | None,
        health_path: Path | None = None,
        model_factory: Callable[[RouteConfig, str | None, dict[str, str] | None], Model]
        | None = None,
        route_reloader: Callable[[], tuple[object, list[RouteConfig]]] | None = None,
        stream_idle_timeout: float = 300.0,
        max_attempts_per_route: int = 2,
        max_attempts_per_turn: int = 3,
        max_consecutive_failed_turns: int = 3,
        max_retry_input_multiplier: float = 2.0,
        allow_unknown_capabilities: bool = True,
        notifications: NotificationPublisher | None = None,
    ) -> None:
        enabled = [route for route in routes if route.enabled]
        if not enabled:
            raise ValueError("at least one enabled model route is required")
        lowered = [route.name.casefold() for route in routes]
        if len(lowered) != len(set(lowered)):
            raise ValueError("route names must be unique")
        self.states = {route.name: RouteState(route) for route in routes}
        self.wait_timeout = wait_timeout
        self.health_path = health_path
        self.run_id = health_path.parent.parent.name if health_path else "setup"
        self._condition = asyncio.Condition()
        self._models: dict[tuple[str, int, str], Model] = {}
        self._retired_models: list[Model] = []
        self._model_factory = model_factory or _default_model_factory
        self._route_reloader = route_reloader
        self._route_revision: object | None = None
        self.stream_idle_timeout = max(0.0, stream_idle_timeout)
        self.max_attempts_per_route = max(1, max_attempts_per_route)
        self.max_attempts_per_turn = max(1, min(3, max_attempts_per_turn))
        self.max_consecutive_failed_turns = max(1, max_consecutive_failed_turns)
        self.max_retry_input_multiplier = max(1.0, max_retry_input_multiplier)
        self.allow_unknown_capabilities = allow_unknown_capabilities
        self._notifications = notifications
        self.decision_path = health_path.with_name("route-decisions.jsonl") if health_path else None
        self._last_decision: RouteDecision | None = None
        self._consecutive_failed_logical_turns = 0
        self._restore_health()

    def _notify(self, event_type: str, **kwargs: Any) -> None:
        if self._notifications is None:
            return
        try:
            self._notifications.publish(event_type, **kwargs)
        except (OSError, RuntimeError, TypeError, ValueError):
            logger.exception("notification publication failed for %s", event_type)

    @property
    def route_models(self) -> tuple[str, ...]:
        return tuple(state.config.model for state in self.states.values() if state.config.enabled)

    def _unavailable_error(self, fallback: str) -> AllRoutesUnavailableError:
        """Turn durable route health into a useful operator-facing failure."""
        for state in sorted(self.states.values(), key=lambda item: item.config.priority):
            last_error = state.last_error or {}
            category = last_error.get("category")
            route = state.config.name
            model = state.config.model
            if category == "provider_incompatible":
                return AllRoutesUnavailableError(
                    f"Configured model '{model}' is unavailable on route '{route}'. "
                    "Select a model exposed by the provider with /models in the TUI."
                )
            if category == "provider_authentication":
                return AllRoutesUnavailableError(
                    f"Route '{route}' needs valid provider credentials. "
                    "Update the connection and test it again."
                )
            if category == "provider_billing":
                return AllRoutesUnavailableError(
                    f"Route '{route}' has no available provider credit. "
                    "Add credit or select another route."
                )
        return AllRoutesUnavailableError(fallback)

    def context_model(self) -> str:
        candidates = [state for state in self.states.values() if state.config.enabled]
        return min(candidates, key=lambda state: state.context_capacity()).config.model

    def context_capacity(self) -> int:
        candidates = [state for state in self.states.values() if state.config.enabled]
        return min(state.context_capacity() for state in candidates)

    def public_status(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        return [
            {
                **state.config.public_dict(),
                "active": state.active,
                "effective_concurrency": state.effective_concurrency,
                "circuit_state": state.circuit_state(now),
                "health": (
                    "disabled"
                    if not state.config.enabled or state.disabled_for_run
                    else "blocked"
                    if state.blocked_reason
                    else "cooldown"
                    if state.cooldown_until > now
                    else "healthy"
                ),
                "cooldown_seconds": max(0, round(state.cooldown_until - now, 1)),
                "blocked_reason": state.blocked_reason,
                "successful_turns": state.successful_turns,
                "failed_turns": state.failed_turns,
                "input_tokens": state.input_tokens,
                "output_tokens": state.output_tokens,
                "attempted_input_tokens": state.attempted_input_tokens,
                "retry_waste_tokens": state.retry_waste_tokens,
                "last_request_input_tokens": state.last_request_input_tokens,
                "last_reserved_output_tokens": state.last_reserved_output_tokens,
                "context_usage_tokens": (
                    state.last_request_input_tokens + state.last_reserved_output_tokens
                ),
                "context_window_tokens": state.context_capacity(),
                "learned_context_window_tokens": state.learned_context_window,
                "next_retry_seconds": max(0, round(state.cooldown_until - now, 1)),
                "last_progress_at": state.last_progress_at,
                "latency_ms_ewma": round(state.latency_ms_ewma, 2),
                "last_error": state.last_error,
            }
            for state in sorted(
                self.states.values(),
                key=lambda item: (item.config.priority, item.config.name),
            )
        ]

    @property
    def last_decision(self) -> RouteDecision | None:
        return self._last_decision

    async def close(self) -> None:
        for model in (*self._models.values(), *self._retired_models):
            with contextlib.suppress(Exception):
                await model.close()
        self._models.clear()
        self._retired_models.clear()

    async def _refresh_route_configuration(self) -> None:
        if self._route_reloader is None:
            return
        try:
            revision, routes = self._route_reloader()
        except Exception:  # noqa: BLE001 - retain the last usable in-memory pool.
            logger.debug("Could not refresh route configuration", exc_info=True)
            return
        if revision == self._route_revision:
            return
        async with self._condition:
            if revision == self._route_revision:
                return
            old_states = self.states
            refreshed: dict[str, RouteState] = {}
            for route in routes:
                existing = old_states.get(route.name)
                if existing is None:
                    refreshed[route.name] = RouteState(route)
                    continue
                existing.config = route
                existing.blocked_reason = None
                existing.disabled_for_run = False
                existing.cooldown_until = 0.0
                existing.consecutive_failures = 0
                existing.probe_in_flight = False
                existing.effective_concurrency = min(
                    max(1, existing.effective_concurrency), route.max_concurrency
                )
                refreshed[route.name] = existing
            if any(state.config.enabled for state in refreshed.values()):
                self.states = refreshed
                self._retired_models.extend(self._models.values())
                self._models.clear()
                self._route_revision = revision
                self._persist_health()
                self._condition.notify_all()

    async def _acquire(  # noqa: PLR0912, PLR0915 - admission handles independent limits.
        self,
        *,
        request: RoutingRequest,
        request_text: str | None = None,
        exclude: set[str] | None = None,
        deadline: float | None = None,
    ) -> RouteState:
        started = time.monotonic()
        excluded = exclude or set()
        while True:
            await self._refresh_route_configuration()
            async with self._condition:
                now = time.monotonic()
                if request.requires_tools:
                    for state in self.states.values():
                        if (
                            state.config.enabled
                            and not state.disabled_for_run
                            and self._lacks_capability(state, "tools")
                        ):
                            state.disabled_for_run = True
                            self._notify(
                                "runtime.route.incompatible",
                                title=f"Route {state.config.name} does not support tools",
                                severity="error",
                                route_id=state.config.name,
                                dedupe_key=f"route-tools:{self.run_id}:{state.config.name}",
                                run_id=self.run_id,
                                actions=(
                                    NotificationAction(
                                        "open_routes", "Open routes", state.config.name
                                    ),
                                ),
                            )
                rejected: dict[str, str] = {}
                candidates: list[RouteState] = []
                for state in self.states.values():
                    reason = self._rejection_reason(
                        state,
                        request=request,
                        request_text=request_text,
                        excluded=excluded,
                        now=now,
                    )
                    if reason is None:
                        candidates.append(state)
                    else:
                        rejected[state.config.name] = reason
                if candidates:
                    selected = min(candidates, key=lambda state: self._rank(state, request))
                    selected.active += 1
                    if selected.consecutive_failures:
                        selected.probe_in_flight = True
                    selected.calls.append(now)
                    selected.attempted_input_tokens += self._route_input_tokens(
                        selected, request.estimated_input_tokens, request_text
                    )
                    selected.last_request_input_tokens = self._route_input_tokens(
                        selected, request.estimated_input_tokens, request_text
                    )
                    selected.last_reserved_output_tokens = request.estimated_output_tokens
                    selected.last_progress_at = time.time()
                    self._record_decision(selected, request, rejected)
                    return selected

                configured = [
                    state
                    for state in self.states.values()
                    if state.config.name not in excluded
                    and state.config.enabled
                    and not state.disabled_for_run
                ]
                capacity_viable = [
                    state
                    for state in configured
                    if state.context_capacity()
                    > self._route_input_tokens(state, request.estimated_input_tokens, request_text)
                    + request.estimated_output_tokens
                ]
                if configured and not capacity_viable:
                    raise RouteContextOverflowError(
                        "context window capacity is too small on every healthy model route"
                    )
                if not capacity_viable:
                    raise self._unavailable_error("all model routes are disabled or blocked")
                # Interactive calls yield to the execution loop when capacity is
                # cooling down, rate-limited, or administratively blocked. That
                # lets the agent become visibly parked and wake through
                # ``wait_until_available``. Ordinary concurrency contention stays
                # inside this condition and does not churn agent lifecycle state.
                if self.wait_timeout is None:
                    merely_busy = any(
                        state.blocked_reason is None
                        and state.cooldown_until <= now
                        and self._within_rate_limits(
                            state,
                            now,
                            input_tokens=self._route_input_tokens(
                                state, request.estimated_input_tokens, request_text
                            ),
                        )
                        and state.active >= state.effective_concurrency
                        for state in capacity_viable
                    )
                    if not merely_busy:
                        raise AllRoutesUnavailableError(
                            "all model routes are temporarily unavailable"
                        )
                elapsed = now - started
                timed_out = deadline is not None and now >= deadline
                if deadline is None and self.wait_timeout is not None:
                    timed_out = elapsed >= self.wait_timeout
                if timed_out:
                    raise AllRoutesUnavailableError(
                        f"all model routes remained unavailable for {self.wait_timeout:.0f}s"
                    )
                next_ready = min(
                    [
                        state.cooldown_until
                        for state in capacity_viable
                        if state.cooldown_until > now
                    ]
                    or [now + 1.0]
                )
                delay = max(0.05, min(1.0, next_ready - now))
                if deadline is not None:
                    delay = min(delay, max(0.05, deadline - now))
                elif self.wait_timeout is not None:
                    delay = min(delay, max(0.05, self.wait_timeout - elapsed))
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._condition.wait(), timeout=delay)

    def _lacks_capability(self, state: RouteState, capability: str) -> bool:
        declared = getattr(state.config, f"supports_{capability}", None)
        if declared is False:
            return True
        if declared is None and not self.allow_unknown_capabilities:
            return True
        if capability == "tools" and declared is None:
            return _explicitly_lacks_tool_support(state.config.model)
        return False

    def _rejection_reason(  # noqa: PLR0911, PLR0912 - explicit contract reasons.
        self,
        state: RouteState,
        *,
        request: RoutingRequest,
        request_text: str | None,
        excluded: set[str],
        now: float,
    ) -> str | None:
        if state.config.name in excluded:
            return "already_attempted"
        if not state.config.enabled or state.disabled_for_run:
            return "disabled"
        if state.blocked_reason:
            return f"blocked:{state.blocked_reason}"
        if state.cooldown_until > now:
            return "circuit_open"
        if state.active >= state.effective_concurrency:
            return "concurrency_limit"
        if state.consecutive_failures and state.probe_in_flight:
            return "probe_in_flight"
        if not self.allow_unknown_capabilities and state.config.metadata_confidence in {
            None,
            "unknown",
        }:
            return "metadata_unverified"
        if request.requires_tools and self._lacks_capability(state, "tools"):
            return "tools_not_verified"
        if request.requires_vision and self._lacks_capability(state, "vision"):
            return "vision_not_verified"
        route_input = self._route_input_tokens(state, request.estimated_input_tokens, request_text)
        if state.context_capacity() <= route_input + request.estimated_output_tokens:
            return "context_too_small"
        if (
            state.config.max_output_tokens is not None
            and state.config.max_output_tokens < request.estimated_output_tokens
        ):
            return "output_limit_too_small"
        if not self._within_rate_limits(state, now, input_tokens=route_input):
            return "rate_limited"
        estimated_cost = self._estimated_cost(state, request, route_input)
        if (
            request.budget_remaining_usd is not None
            and estimated_cost is not None
            and estimated_cost > request.budget_remaining_usd
        ):
            return "over_budget"
        return None

    @staticmethod
    def _estimated_cost(
        state: RouteState, request: RoutingRequest, route_input: int
    ) -> float | None:
        input_cost = state.config.input_cost_per_million
        output_cost = state.config.output_cost_per_million
        if input_cost is None or output_cost is None:
            return None
        return (
            route_input * input_cost + request.estimated_output_tokens * output_cost
        ) / 1_000_000

    def _rank(self, state: RouteState, request: RoutingRequest) -> tuple[Any, ...]:
        total = state.successful_turns + state.failed_turns
        failure_rate = state.failed_turns / total if total else 0.0
        capability_fit = 0.0
        if request.prefers_reasoning and state.config.supports_reasoning is not True:
            capability_fit += 1
        if request.task_kind in {"coding", "recon"} and state.config.supports_tools is not True:
            capability_fit += 1
        if request.task_kind == "long_context":
            capability_fit -= min(state.context_capacity(), 2_000_000) / 2_000_000
        route_input = max(1, request.estimated_input_tokens)
        cost = self._estimated_cost(state, request, route_input)
        return (
            _QUALITY_RANK.get(state.config.quality_tier, _QUALITY_RANK["unknown"]),
            failure_rate,
            capability_fit,
            float("inf") if cost is None else cost,
            state.latency_ms_ewma if state.latency_ms_ewma > 0 else float("inf"),
            state.config.name,
        )

    def _record_decision(
        self,
        state: RouteState,
        request: RoutingRequest,
        rejected: dict[str, str],
    ) -> None:
        reason = (
            f"quality={state.config.quality_tier}; reliability="
            f"{state.successful_turns}/{state.successful_turns + state.failed_turns}; "
            f"capabilities=tools:{state.config.supports_tools},"
            f"vision:{state.config.supports_vision},reasoning:{state.config.supports_reasoning}"
        )
        decision = RouteDecision(
            route_id=state.config.name,
            model=state.config.model,
            reason=reason,
            rejected=dict(sorted(rejected.items())),
            request=request,
        )
        self._last_decision = decision
        if self.decision_path is None:
            return
        try:
            self.decision_path.parent.mkdir(parents=True, exist_ok=True)
            with self.decision_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(asdict(decision), sort_keys=True) + "\n")
        except OSError:
            logger.exception("failed to persist sanitized route decision")

    def _record_logical_failure(self) -> None:
        self._consecutive_failed_logical_turns += 1
        if self._consecutive_failed_logical_turns < self.max_consecutive_failed_turns:
            return
        for state in self.states.values():
            state.blocked_reason = "three consecutive logical turns failed; user action required"
        self._persist_health()
        self._notify(
            "runtime.router.circuit_open",
            title="Automatic router paused after three failed turns",
            detail="Review /router and /connect before resuming the scan.",
            severity="error",
            dedupe_key=f"router-circuit:{self.run_id}",
            run_id=self.run_id,
            actions=(NotificationAction("open_routes", "Open router", None),),
        )

    def _record_logical_success(self) -> None:
        self._consecutive_failed_logical_turns = 0

    async def wait_until_available(
        self,
        *,
        input_tokens: int = 1,
        output_tokens: int = 4_096,
        requires_tools: bool = True,
    ) -> None:
        """Wait until at least one route can accept work without reserving it."""
        while True:
            await self._refresh_route_configuration()
            async with self._condition:
                now = time.monotonic()
                if any(
                    state.available(now)
                    and state.context_capacity() > input_tokens + output_tokens
                    and (not requires_tools or not self._lacks_capability(state, "tools"))
                    and self._within_rate_limits(state, now, input_tokens=input_tokens)
                    for state in self.states.values()
                ):
                    return
                await self._wait_for_health_change(now)

    async def _wait_for_health_change(self, now: float) -> None:
        next_ready = min(
            [state.cooldown_until for state in self.states.values() if state.cooldown_until > now]
            or [now + 1.0]
        )
        delay = max(0.05, min(1.0, next_ready - now))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._condition.wait(), timeout=delay)

    @staticmethod
    def _within_rate_limits(state: RouteState, now: float, *, input_tokens: int) -> bool:
        minute_ago = now - 60.0
        while state.calls and state.calls[0] < minute_ago:
            state.calls.popleft()
        while state.usage and state.usage[0].timestamp < minute_ago:
            state.usage.popleft()
        if state.config.rpm is not None and len(state.calls) >= state.config.rpm:
            return False
        if state.config.tpm is not None:
            recent = sum(entry.tokens for entry in state.usage)
            if recent + input_tokens > state.config.tpm:
                return False
        return True

    @staticmethod
    def _route_input_tokens(state: RouteState, fallback: int, request_text: str | None) -> int:
        if request_text is None:
            return fallback
        return max(1, count_tokens(state.config.model, request_text))

    async def _release(
        self,
        state: RouteState,
        *,
        response: ModelResponse | None = None,
        error: BaseException | None = None,
        attempted_input_tokens: int = 0,
        latency_ms: float | None = None,
    ) -> RouteFailureKind | None:
        failure_kind = classify_route_failure(error) if error is not None else None
        async with self._condition:
            state.active = max(0, state.active - 1)
            state.last_progress_at = time.time()
            if response is not None:
                usage = getattr(response, "usage", None)
                input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
                output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
                state.input_tokens += input_tokens
                state.output_tokens += output_tokens
                state.usage.append(_UsageEntry(time.monotonic(), input_tokens + output_tokens))
                recovered = state.consecutive_failures > 0 or state.cooldown_until > 0
                state.consecutive_failures = 0
                state.cooldown_until = 0.0
                state.probe_in_flight = False
                if recovered:
                    state.effective_concurrency = min(
                        state.config.max_concurrency, state.effective_concurrency + 1
                    )
                state.successful_turns += 1
                if latency_ms is not None:
                    state.latency_ms_ewma = (
                        latency_ms
                        if state.latency_ms_ewma <= 0
                        else state.latency_ms_ewma * 0.8 + latency_ms * 0.2
                    )
                if recovered:
                    self._notify(
                        "runtime.route.recovered",
                        title=f"Route {state.config.name} recovered",
                        severity="info",
                        route_id=state.config.name,
                        dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                        run_id=self.run_id,
                    )
            elif error is not None:
                state.failed_turns += 1
                state.retry_waste_tokens += max(0, attempted_input_tokens)
                state.last_error = error_envelope(
                    error,
                    attempt=state.consecutive_failures + 1,
                    retry_after=retry_after_seconds(error),
                ).to_dict()
                await self._apply_failure(
                    state,
                    error,
                    cast("RouteFailureKind", failure_kind),
                    attempted_input_tokens=attempted_input_tokens,
                )
            self._persist_health()
            self._condition.notify_all()
        return failure_kind

    async def _apply_failure(
        self,
        state: RouteState,
        error: BaseException,
        kind: RouteFailureKind,
        *,
        attempted_input_tokens: int = 0,
    ) -> None:
        safe_error = redact_secrets(error)
        if kind == "transient":
            state.consecutive_failures += 1
            state.probe_in_flight = False
            state.effective_concurrency = max(1, state.effective_concurrency // 2)
            delay = full_jitter_delay(
                state.consecutive_failures,
                base_delay=2.0,
                max_delay=90.0,
                retry_after=retry_after_seconds(error),
            )
            state.cooldown_until = time.monotonic() + max(0.25, delay)
            self._notify(
                "runtime.route.cooldown",
                title=f"Route {state.config.name} is cooling down",
                detail=safe_error,
                severity="warning",
                route_id=state.config.name,
                dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                run_id=self.run_id,
                actions=(NotificationAction("retry_route_test", "Test route", state.config.name),),
            )
        elif kind in {"authentication", "billing"}:
            state.probe_in_flight = False
            state.blocked_reason = (
                "billing or quota failure" if kind == "billing" else "credential failure"
            )
            self._notify(
                "model.billing" if kind == "billing" else "security.credential_required",
                title=f"Route {state.config.name} needs attention",
                detail=safe_error,
                severity="error",
                route_id=state.config.name,
                dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                run_id=self.run_id,
                actions=(NotificationAction("open_routes", "Open routes", state.config.name),),
            )
        elif kind == "incompatible":
            state.probe_in_flight = False
            state.disabled_for_run = True
            self._notify(
                "runtime.route.incompatible",
                title=f"Route {state.config.name} is incompatible with this scan",
                detail=safe_error,
                severity="error",
                route_id=state.config.name,
                dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                run_id=self.run_id,
                actions=(NotificationAction("open_routes", "Open routes", state.config.name),),
            )
        elif kind == "context" and attempted_input_tokens:
            state.probe_in_flight = False
            observed_ceiling = max(4_096, attempted_input_tokens - 1)
            state.learned_context_window = min(state.context_capacity(), observed_ceiling)
        else:
            state.probe_in_flight = False

    def _persist_health(self) -> None:
        if self.health_path is None:
            return
        try:
            self.health_path.parent.mkdir(parents=True, exist_ok=True)
            write_secret_text(
                self.health_path,
                json.dumps({"version": 1, "routes": self.public_status()}, indent=2),
            )
        except OSError:
            logger.exception("failed to persist sanitized route health")

    def _restore_health(self) -> None:  # noqa: PLR0912 - validates persisted fields independently.
        """Restore durable counters and learned limits, never transient leases."""
        if self.health_path is None:
            return
        try:
            payload = json.loads(self.health_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return
        routes = payload.get("routes") if isinstance(payload, dict) else None
        if not isinstance(routes, list):
            return
        for raw in routes:
            if not isinstance(raw, dict):
                continue
            state = self.states.get(str(raw.get("name") or ""))
            if state is None or raw.get("model") != state.config.model:
                continue
            learned = raw.get("learned_context_window_tokens")
            if isinstance(learned, int) and learned >= 4_096:
                state.learned_context_window = min(
                    learned, state.config.context_window_tokens or learned
                )
            for name in (
                "successful_turns",
                "failed_turns",
                "input_tokens",
                "output_tokens",
                "attempted_input_tokens",
                "retry_waste_tokens",
                "last_request_input_tokens",
                "last_reserved_output_tokens",
            ):
                value = raw.get(name)
                if isinstance(value, int) and value >= 0:
                    setattr(state, name, value)
            effective = raw.get("effective_concurrency")
            if isinstance(effective, int) and effective > 0:
                state.effective_concurrency = min(effective, state.config.max_concurrency)
            last_error = raw.get("last_error")
            if isinstance(last_error, dict):
                state.last_error = last_error
            last_progress = raw.get("last_progress_at")
            if isinstance(last_progress, int | float) and last_progress > 0:
                state.last_progress_at = float(last_progress)
            latency = raw.get("latency_ms_ewma")
            if isinstance(latency, int | float) and latency >= 0:
                state.latency_ms_ewma = float(latency)

    def _model(self, route: RouteConfig) -> Model:
        cache_key = (route.name, route.connection_revision, route.model)
        existing = self._models.get(cache_key)
        if existing is not None:
            return existing
        key, headers = _resolve_route_secrets(route)
        model = self._model_factory(route, key, headers)
        self._models[cache_key] = model
        return model

    async def get_response(self, **kwargs: Any) -> ModelResponse:
        attempted: set[str] = set()
        request_text = _request_payload_text(kwargs)
        input_tokens = _request_token_estimate(kwargs)
        output_tokens = _request_output_limit(kwargs)
        requires_tools = bool(kwargs.get("tools"))
        request = _routing_request(
            kwargs,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            requires_tools=requires_tools,
        )
        request_kwargs = _without_nested_retry(kwargs)
        deadline = time.monotonic() + self.wait_timeout if self.wait_timeout is not None else None
        attempts = 0
        max_attempts = min(
            self.max_attempts_per_turn,
            1 + int(self.max_retry_input_multiplier),
            len(self.states),
        )
        while True:
            if attempts >= max_attempts:
                self._record_logical_failure()
                raise self._unavailable_error(
                    f"model route connection attempts exhausted after {attempts} attempts"
                )
            state = await self._acquire(
                request=request,
                request_text=request_text,
                exclude=attempted,
                deadline=deadline,
            )
            attempted.add(state.config.name)
            attempts += 1
            route_input_tokens = self._route_input_tokens(state, input_tokens, request_text)
            attempt_started = time.monotonic()
            try:
                response = await self._model(state.config).get_response(**request_kwargs)
            except Exception as exc:
                kind = await self._release(
                    state, error=exc, attempted_input_tokens=route_input_tokens
                )
                if kind == "context":
                    if any(
                        candidate.config.enabled
                        and not candidate.disabled_for_run
                        and candidate.config.name not in attempted
                        for candidate in self.states.values()
                    ):
                        continue
                    raise
                if kind in {"transient", "authentication", "billing", "incompatible"}:
                    continue
                raise
            await self._release(
                state,
                response=response,
                latency_ms=(time.monotonic() - attempt_started) * 1_000,
            )
            self._record_logical_success()
            _tag_response_route(response, state.config)
            return response

    async def stream_response(self, **kwargs: Any) -> AsyncIterator[TResponseStreamEvent]:
        attempted: set[str] = set()
        request_text = _request_payload_text(kwargs)
        input_tokens = _request_token_estimate(kwargs)
        output_tokens = _request_output_limit(kwargs)
        requires_tools = bool(kwargs.get("tools"))
        request = _routing_request(
            kwargs,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            requires_tools=requires_tools,
        )
        request_kwargs = _without_nested_retry(kwargs)
        deadline = time.monotonic() + self.wait_timeout if self.wait_timeout is not None else None
        attempts = 0
        max_attempts = min(
            self.max_attempts_per_turn,
            1 + int(self.max_retry_input_multiplier),
            len(self.states),
        )
        while True:
            if attempts >= max_attempts:
                self._record_logical_failure()
                raise self._unavailable_error(
                    f"model route connection attempts exhausted after {attempts} attempts"
                )
            state = await self._acquire(
                request=request,
                request_text=request_text,
                exclude=attempted,
                deadline=deadline,
            )
            attempted.add(state.config.name)
            attempts += 1
            route_input_tokens = self._route_input_tokens(state, input_tokens, request_text)
            attempt_started = time.monotonic()
            emitted = False
            final_response = None
            stream = self._model(state.config).stream_response(**request_kwargs)
            try:
                async for event in _with_idle_watchdog(stream, self.stream_idle_timeout):
                    emitted = True
                    response = getattr(event, "response", None)
                    if response is not None:
                        final_response = _model_response_from_event(response)
                        _tag_response_route(response, state.config)
                    yield event
            except Exception as exc:
                kind = await self._release(
                    state, error=exc, attempted_input_tokens=route_input_tokens
                )
                if not emitted and kind == "context":
                    if any(
                        candidate.config.enabled
                        and not candidate.disabled_for_run
                        and candidate.config.name not in attempted
                        for candidate in self.states.values()
                    ):
                        continue
                    raise
                if not emitted and kind in {
                    "transient",
                    "authentication",
                    "billing",
                    "incompatible",
                }:
                    continue
                raise
            await self._release(
                state,
                response=final_response,
                latency_ms=(time.monotonic() - attempt_started) * 1_000,
            )
            if final_response is not None:
                self._record_logical_success()
            return


class RoutedModel(Model):
    def __init__(self, pool: RoutePool) -> None:
        self.pool = pool

    async def close(self) -> None:
        await self.pool.close()

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> ModelResponse:
        return await self.pool.get_response(
            system_instructions=system_instructions,
            input=input,
            model_settings=model_settings,
            tools=tools,
            output_schema=output_schema,
            handoffs=handoffs,
            tracing=tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        async for event in self.pool.stream_response(
            system_instructions=system_instructions,
            input=input,
            model_settings=model_settings,
            tools=tools,
            output_schema=output_schema,
            handoffs=handoffs,
            tracing=tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        ):
            yield event


class SmartRouteProvider(ModelProvider):
    """SDK provider returning one shared routed model regardless of placeholder name."""

    def __init__(self, pool: RoutePool) -> None:
        self.pool = pool
        self._model = RoutedModel(pool)

    def get_model(self, model_name: str | None) -> Model:
        del model_name
        return self._model


def _resolve_route_secrets(route: RouteConfig) -> tuple[str | None, dict[str, str] | None]:
    store = get_secret_store()
    api_key = os.environ.get(route.api_key_env, "") if route.api_key_env else None
    if not api_key and route.api_key_ref:
        api_key = store.get(route.api_key_ref)
    raw_headers = os.environ.get(route.headers_env, "") if route.headers_env else None
    if not raw_headers and route.headers_ref:
        raw_headers = store.get(route.headers_ref)
    register_secret(api_key)
    register_secret(raw_headers)
    headers: dict[str, str] | None = None
    if raw_headers:
        try:
            parsed = cast("object", json.loads(raw_headers))
        except json.JSONDecodeError as exc:
            raise ValueError(f"route {route.name} headers secret is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"route {route.name} headers secret must be a JSON string map")
        raw_map = cast("dict[object, object]", parsed)
        if not all(
            isinstance(key, str) and isinstance(value, str) for key, value in raw_map.items()
        ):
            raise ValueError(f"route {route.name} headers secret must be a JSON string map")
        headers = cast("dict[str, str]", raw_map)
    return api_key or None, headers


resolve_route_secrets = _resolve_route_secrets


def _default_model_factory(
    route: RouteConfig, api_key: str | None, headers: dict[str, str] | None
) -> Model:
    # Imported lazily to avoid a cycle: config.models owns provider construction
    # and imports no routing state.
    from strix.config.models import StrixProvider  # noqa: PLC0415

    inner = StrixProvider(api_key=api_key, base_url=route.base_url).get_model(route.model)
    if headers:
        inner = _HeaderModel(inner, headers)
    return _LiveSettingsModel(inner, route.model)


class _LiveSettingsModel(Model):
    """Capture current UI settings once at each provider-call boundary."""

    def __init__(self, inner: Model, model_name: str) -> None:
        self.inner = inner
        self.model_name = model_name

    async def close(self) -> None:
        await self.inner.close()

    def _settings(self, original: ModelSettings) -> ModelSettings:
        from strix.config.app_config import get_config_service  # noqa: PLC0415
        from strix.core.inputs import make_model_settings  # noqa: PLC0415

        current = get_config_service().load().ui
        fresh = make_model_settings(
            current.reasoning_effort,
            model_name=self.model_name,
            request_timeout=current.llm_timeout_seconds,
            prompt_cache=current.prompt_cache,
            extra_headers=None,
        )
        original_body: object = getattr(original, "extra_body", None)
        fresh_body: object = getattr(fresh, "extra_body", None)
        extra_body: dict[str, Any] = (
            dict(cast("dict[str, Any]", original_body)) if isinstance(original_body, dict) else {}
        )
        extra_body.pop("reasoning_effort", None)
        if isinstance(fresh_body, dict):
            extra_body.update(cast("dict[str, Any]", fresh_body))
        return replace(
            original,
            reasoning=fresh.reasoning,
            tool_choice=fresh.tool_choice or original.tool_choice,
            extra_args=fresh.extra_args,
            extra_body=extra_body or None,
            extra_headers=fresh.extra_headers,
        )

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        kwargs["model_settings"] = self._settings(kwargs["model_settings"])
        return await self.inner.get_response(*args, **kwargs)

    async def stream_response(
        self, *args: Any, **kwargs: Any
    ) -> AsyncIterator[TResponseStreamEvent]:
        kwargs["model_settings"] = self._settings(kwargs["model_settings"])
        async for event in self.inner.stream_response(*args, **kwargs):
            yield event


class _HeaderModel(Model):
    def __init__(self, inner: Model, headers: dict[str, str]) -> None:
        self.inner = inner
        self.headers = headers

    async def close(self) -> None:
        await self.inner.close()

    @staticmethod
    def _settings(settings: ModelSettings, headers: dict[str, str]) -> ModelSettings:
        return settings.resolve(
            ModelSettings(extra_headers={**(settings.extra_headers or {}), **headers})
        )

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        if len(args) >= 3:
            args = (*args[:2], self._settings(args[2], self.headers), *args[3:])
        elif "model_settings" in kwargs:
            kwargs["model_settings"] = self._settings(kwargs["model_settings"], self.headers)
        return await self.inner.get_response(*args, **kwargs)

    async def stream_response(
        self, *args: Any, **kwargs: Any
    ) -> AsyncIterator[TResponseStreamEvent]:
        if len(args) >= 3:
            args = (*args[:2], self._settings(args[2], self.headers), *args[3:])
        elif "model_settings" in kwargs:
            kwargs["model_settings"] = self._settings(kwargs["model_settings"], self.headers)
        async for event in self.inner.stream_response(*args, **kwargs):
            yield event


def _request_payload_text(kwargs: dict[str, Any]) -> str:
    """Render every provider-visible request surface for route-aware metering."""

    def normalize(value: Any) -> Any:
        if value is None or isinstance(value, str | int | float | bool):
            return value
        if isinstance(value, dict):
            return {str(key): normalize(item) for key, item in value.items()}
        if isinstance(value, list | tuple):
            return [normalize(item) for item in value]
        if hasattr(value, "model_dump"):
            with contextlib.suppress(Exception):
                return normalize(value.model_dump(exclude_none=True))
        public: dict[str, Any] = {}
        for name in (
            "name",
            "description",
            "params_json_schema",
            "input_json_schema",
            "strict_json_schema",
        ):
            attribute = getattr(value, name, None)
            if attribute is not None:
                public[name] = normalize(attribute)
        return public or type(value).__name__

    provider_visible = {
        key: normalize(value)
        for key, value in kwargs.items()
        if key
        in {
            "system_instructions",
            "input",
            "tools",
            "output_schema",
            "handoffs",
            "prompt",
            "previous_response_id",
            "conversation_id",
        }
    }
    try:
        return json.dumps(
            provider_visible, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError):
        return str(provider_visible)


def _request_token_estimate(kwargs: dict[str, Any]) -> int:
    # This model-neutral number is used only as a fallback by tests and direct
    # callers. Route admission meters the complete rendered payload with the
    # selected model's tokenizer (or a conservative UTF-8 upper bound).
    return max(1, len(_request_payload_text(kwargs).encode("utf-8")))


def _routing_request(
    kwargs: dict[str, Any],
    *,
    input_tokens: int,
    output_tokens: int,
    requires_tools: bool,
) -> RoutingRequest:
    context = _routing_context.get() or {}
    raw_kind = str(context.get("task_kind") or "general")
    task_kind: TaskKind = (
        cast("TaskKind", raw_kind)
        if raw_kind in {"recon", "coding", "long_context", "vision", "general"}
        else "general"
    )
    requires_vision = task_kind == "vision" or _contains_image_input(kwargs.get("input"))
    remaining = context.get("budget_remaining_usd")
    return RoutingRequest(
        agent_role=str(context.get("agent_role") or "agent"),
        scan_phase=str(context.get("scan_phase") or "analysis"),
        task_kind=task_kind,
        requires_tools=requires_tools,
        requires_vision=requires_vision,
        prefers_reasoning=bool(context.get("prefers_reasoning", task_kind == "coding")),
        estimated_input_tokens=input_tokens,
        estimated_output_tokens=output_tokens,
        budget_remaining_usd=float(remaining) if isinstance(remaining, int | float) else None,
    )


def _contains_image_input(value: Any) -> bool:
    if isinstance(value, dict):
        kind = str(value.get("type") or "").casefold()
        if kind in {"input_image", "image", "image_url"}:
            return True
        return any(_contains_image_input(item) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_image_input(item) for item in value)
    if hasattr(value, "model_dump"):
        with contextlib.suppress(Exception):
            return _contains_image_input(value.model_dump(exclude_none=True))
    return False


async def _with_idle_watchdog(
    stream: AsyncIterator[TResponseStreamEvent], timeout: float
) -> AsyncIterator[TResponseStreamEvent]:
    iterator = stream.__aiter__()
    while True:
        try:
            if timeout > 0:
                event = await asyncio.wait_for(anext(iterator), timeout=timeout)
            else:
                event = await anext(iterator)
        except StopAsyncIteration:
            return
        except TimeoutError as exc:
            raise TimeoutError(f"model stream made no progress for {timeout:g}s") from exc
        yield event


def _without_nested_retry(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Make the shared route pool the sole request-level retry owner."""
    settings = kwargs.get("model_settings")
    if not isinstance(settings, ModelSettings) or settings.retry is None:
        return kwargs
    return {**kwargs, "model_settings": replace(settings, retry=None)}


@lru_cache(maxsize=128)
def _explicitly_lacks_tool_support(model: str) -> bool:
    """Reject only models whose local metadata explicitly says tools are unsupported."""
    try:
        candidates = [model]
        if "/" in model:
            candidates.append(model.split("/", 1)[1])
        for candidate in candidates:
            with contextlib.suppress(Exception):
                value = litellm.get_model_info(candidate).get("supports_function_calling")
                if value is not None:
                    return value is False
    except Exception:  # noqa: BLE001 - unknown/custom models are tried optimistically.
        logger.debug("Could not resolve tool metadata for %r", model, exc_info=True)
    return False


def _request_output_limit(kwargs: dict[str, Any]) -> int:
    settings = kwargs.get("model_settings")
    requested = getattr(settings, "max_tokens", None)
    return requested if isinstance(requested, int) and requested > 0 else 4_096


def _model_response_from_event(response: Any) -> ModelResponse | None:
    # The SDK accounts final stream usage itself. This lightweight object is
    # only for route counters and is deliberately duck-typed.
    usage = getattr(response, "usage", None)
    if usage is None:
        return None

    class _Response:
        usage: Any

    result = _Response()
    result.usage = usage
    return cast("ModelResponse", result)


def _tag_response_route(response: Any, route: RouteConfig) -> None:
    """Attach non-secret attribution consumed by run usage hooks."""
    for name, value in (
        ("_strix_route_name", route.name),
        ("_strix_model_name", route.model),
    ):
        with contextlib.suppress(Exception):
            object.__setattr__(response, name, value)
