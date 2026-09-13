"""Health-aware shared model routing for Strix agents."""

from __future__ import annotations

import asyncio
import contextlib
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

from strix.llm.context_budget import context_window
from strix.notifications import NotificationAction, notify
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


logger = logging.getLogger(__name__)

RouteFailureKind = Literal[
    "transient",
    "authentication",
    "context",
    "policy",
    "incompatible",
    "fatal",
]


@dataclass(slots=True)
class RouteConfig:
    """Persistable, non-secret route definition."""

    name: str
    model: str
    base_url: str | None = None
    priority: int = 1
    max_concurrency: int = 2
    rpm: int | None = None
    tpm: int | None = None
    enabled: bool = True
    provider_id: str | None = None
    transport: str | None = None
    model_id: str | None = None
    api_key_ref: str | None = None
    headers_ref: str | None = None
    api_key_env: str | None = field(default=None, repr=False, compare=False)
    headers_env: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.name = self.name.strip()
        self.model = self.model.strip()
        if not self.name or len(self.name) > 80:
            raise ValueError("route name must be 1-80 characters")
        if not self.model:
            raise ValueError("route model cannot be empty")
        if self.priority < 1:
            raise ValueError("route priority must be at least 1")
        if self.max_concurrency < 1:
            raise ValueError("route max_concurrency must be at least 1")
        if self.rpm is not None and self.rpm < 1:
            raise ValueError("route rpm must be at least 1")
        if self.tpm is not None and self.tpm < 1:
            raise ValueError("route tpm must be at least 1")

    @classmethod
    def from_dict(cls, value: dict[str, Any], *, allow_env: bool = False) -> RouteConfig:
        # Explicitly reject likely literal secrets in route files/config.
        forbidden = value.keys() & {"api_key", "key", "token", "headers"}
        if forbidden:
            raise ValueError(
                "route files cannot contain literal secrets; use an environment reference"
            )
        allowed = {
            "name",
            "model",
            "base_url",
            "priority",
            "max_concurrency",
            "rpm",
            "tpm",
            "enabled",
            "provider_id",
            "transport",
            "model_id",
            "api_key_ref",
            "headers_ref",
        }
        if allow_env:
            allowed.update({"api_key_env", "headers_env"})
        extra = value.keys() - allowed
        if extra:
            raise ValueError(f"unsupported route fields: {', '.join(sorted(extra))}")
        return cls(**{key: value[key] for key in allowed if key in value})

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("api_key_env", None)
        result.pop("headers_env", None)
        return {key: value for key, value in result.items() if value is not None}

    def public_dict(self) -> dict[str, Any]:
        result = self.to_dict()
        result["has_api_key"] = bool(self.api_key_ref or self.api_key_env)
        result["has_headers"] = bool(self.headers_ref or self.headers_env)
        return result


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

    def available(self, now: float) -> bool:
        return (
            self.config.enabled
            and not self.disabled_for_run
            and self.blocked_reason is None
            and self.cooldown_until <= now
            and self.active < self.config.max_concurrency
        )


class AllRoutesUnavailableError(RuntimeError):
    """Every configured route is blocked or remained unavailable until timeout."""


class RouteContextOverflowError(RuntimeError):
    """No healthy route has enough context capacity for the pending request."""


def classify_route_failure(exc: BaseException) -> RouteFailureKind:
    from strix.llm.errors import classify_model_failure  # noqa: PLC0415 - avoid config cycle

    kind = classify_model_failure(exc)
    if kind == "billing":
        return "authentication"
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
        self._models: dict[str, Model] = {}
        self._retired_models: list[Model] = []
        self._model_factory = model_factory or _default_model_factory
        self._route_reloader = route_reloader
        self._route_revision: object | None = None

    @property
    def route_models(self) -> tuple[str, ...]:
        return tuple(state.config.model for state in self.states.values() if state.config.enabled)

    def context_model(self) -> str:
        candidates = [state.config.model for state in self.states.values() if state.config.enabled]
        return min(candidates, key=context_window)

    def public_status(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        return [
            {
                **state.config.public_dict(),
                "active": state.active,
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
            }
            for state in sorted(
                self.states.values(),
                key=lambda item: (item.config.priority, item.config.name),
            )
        ]

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
                refreshed[route.name] = existing
            if any(state.config.enabled for state in refreshed.values()):
                self.states = refreshed
                self._retired_models.extend(self._models.values())
                self._models.clear()
                self._route_revision = revision
                self._persist_health()
                self._condition.notify_all()

    async def _acquire(  # noqa: PLR0912 - admission handles every independent limit.
        self,
        *,
        input_tokens: int,
        output_tokens: int,
        requires_tools: bool = False,
        exclude: set[str] | None = None,
        deadline: float | None = None,
    ) -> RouteState:
        started = time.monotonic()
        excluded = exclude or set()
        while True:
            await self._refresh_route_configuration()
            async with self._condition:
                now = time.monotonic()
                if requires_tools:
                    for state in self.states.values():
                        if (
                            state.config.enabled
                            and not state.disabled_for_run
                            and _explicitly_lacks_tool_support(state.config.model)
                        ):
                            state.disabled_for_run = True
                            notify(
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
                candidates = [
                    state
                    for state in self.states.values()
                    if state.config.name not in excluded
                    and state.available(now)
                    and context_window(state.config.model) > input_tokens + output_tokens
                    and self._within_rate_limits(state, now, input_tokens=input_tokens)
                ]
                if candidates:
                    priority = min(state.config.priority for state in candidates)
                    tier = [state for state in candidates if state.config.priority == priority]
                    selected = min(
                        tier,
                        key=lambda state: (
                            state.active / state.config.max_concurrency,
                            state.config.name,
                        ),
                    )
                    selected.active += 1
                    selected.calls.append(now)
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
                    if context_window(state.config.model) > input_tokens + output_tokens
                ]
                if configured and not capacity_viable:
                    raise RouteContextOverflowError(
                        "context window capacity is too small on every healthy model route"
                    )
                if not capacity_viable:
                    raise AllRoutesUnavailableError("all model routes are disabled or blocked")
                # Interactive calls yield to the execution loop when capacity is
                # cooling down, rate-limited, or administratively blocked. That
                # lets the agent become visibly parked and wake through
                # ``wait_until_available``. Ordinary concurrency contention stays
                # inside this condition and does not churn agent lifecycle state.
                if self.wait_timeout is None:
                    merely_busy = any(
                        state.blocked_reason is None
                        and state.cooldown_until <= now
                        and self._within_rate_limits(state, now, input_tokens=input_tokens)
                        and state.active >= state.config.max_concurrency
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
                    and context_window(state.config.model) > input_tokens + output_tokens
                    and (
                        not requires_tools or not _explicitly_lacks_tool_support(state.config.model)
                    )
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

    async def _release(
        self,
        state: RouteState,
        *,
        response: ModelResponse | None = None,
        error: BaseException | None = None,
    ) -> RouteFailureKind | None:
        failure_kind = classify_route_failure(error) if error is not None else None
        async with self._condition:
            state.active = max(0, state.active - 1)
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
                state.successful_turns += 1
                if recovered:
                    notify(
                        "runtime.route.recovered",
                        title=f"Route {state.config.name} recovered",
                        severity="info",
                        route_id=state.config.name,
                        dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                        run_id=self.run_id,
                    )
            elif error is not None:
                state.failed_turns += 1
                await self._apply_failure(state, error, cast("RouteFailureKind", failure_kind))
            self._persist_health()
            self._condition.notify_all()
        return failure_kind

    async def _apply_failure(
        self, state: RouteState, error: BaseException, kind: RouteFailureKind
    ) -> None:
        safe_error = redact_secrets(error)
        if kind == "transient":
            state.consecutive_failures += 1
            delay = full_jitter_delay(
                state.consecutive_failures,
                base_delay=2.0,
                max_delay=90.0,
                retry_after=retry_after_seconds(error),
            )
            state.cooldown_until = time.monotonic() + max(0.25, delay)
            notify(
                "runtime.route.cooldown",
                title=f"Route {state.config.name} is cooling down",
                detail=safe_error,
                severity="warning",
                route_id=state.config.name,
                dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                run_id=self.run_id,
                actions=(NotificationAction("retry_route_test", "Test route", state.config.name),),
            )
        elif kind == "authentication":
            state.blocked_reason = "credential, quota, or billing failure"
            notify(
                "security.credential_required",
                title=f"Route {state.config.name} needs attention",
                detail=safe_error,
                severity="error",
                route_id=state.config.name,
                dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                run_id=self.run_id,
                actions=(NotificationAction("open_routes", "Open routes", state.config.name),),
            )
        elif kind == "incompatible":
            state.disabled_for_run = True
            notify(
                "runtime.route.incompatible",
                title=f"Route {state.config.name} is incompatible with this scan",
                detail=safe_error,
                severity="error",
                route_id=state.config.name,
                dedupe_key=f"route-incident:{self.run_id}:{state.config.name}",
                run_id=self.run_id,
                actions=(NotificationAction("open_routes", "Open routes", state.config.name),),
            )

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

    def _model(self, route: RouteConfig) -> Model:
        existing = self._models.get(route.name)
        if existing is not None:
            return existing
        key, headers = _resolve_route_secrets(route)
        model = self._model_factory(route, key, headers)
        self._models[route.name] = model
        return model

    async def get_response(self, **kwargs: Any) -> ModelResponse:
        attempted: set[str] = set()
        input_tokens = _request_token_estimate(kwargs)
        output_tokens = _request_output_limit(kwargs)
        requires_tools = bool(kwargs.get("tools"))
        request_kwargs = _without_nested_retry(kwargs)
        deadline = time.monotonic() + self.wait_timeout if self.wait_timeout is not None else None
        while True:
            if attempted and not any(
                state.config.enabled
                and not state.disabled_for_run
                and state.config.name not in attempted
                for state in self.states.values()
            ):
                if self.wait_timeout is None:
                    raise AllRoutesUnavailableError("all model routes are temporarily unavailable")
                attempted.clear()
            state = await self._acquire(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                requires_tools=requires_tools,
                exclude=attempted,
                deadline=deadline,
            )
            attempted.add(state.config.name)
            try:
                response = await self._model(state.config).get_response(**request_kwargs)
            except Exception as exc:
                kind = await self._release(state, error=exc)
                if kind in {"transient", "authentication", "incompatible"}:
                    continue
                raise
            await self._release(state, response=response)
            _tag_response_route(response, state.config)
            return response

    async def stream_response(self, **kwargs: Any) -> AsyncIterator[TResponseStreamEvent]:
        attempted: set[str] = set()
        input_tokens = _request_token_estimate(kwargs)
        output_tokens = _request_output_limit(kwargs)
        requires_tools = bool(kwargs.get("tools"))
        request_kwargs = _without_nested_retry(kwargs)
        deadline = time.monotonic() + self.wait_timeout if self.wait_timeout is not None else None
        while True:
            if attempted and not any(
                state.config.enabled
                and not state.disabled_for_run
                and state.config.name not in attempted
                for state in self.states.values()
            ):
                if self.wait_timeout is None:
                    raise AllRoutesUnavailableError("all model routes are temporarily unavailable")
                attempted.clear()
            state = await self._acquire(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                requires_tools=requires_tools,
                exclude=attempted,
                deadline=deadline,
            )
            attempted.add(state.config.name)
            emitted = False
            final_response = None
            stream = self._model(state.config).stream_response(**request_kwargs)
            try:
                async for event in stream:
                    emitted = True
                    response = getattr(event, "response", None)
                    if response is not None:
                        final_response = _model_response_from_event(response)
                        _tag_response_route(response, state.config)
                    yield event
            except Exception as exc:
                kind = await self._release(state, error=exc)
                if not emitted and kind in {"transient", "authentication", "incompatible"}:
                    continue
                raise
            await self._release(state, response=final_response)
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
        from strix.config.loader import load_settings  # noqa: PLC0415
        from strix.core.inputs import make_model_settings  # noqa: PLC0415

        current = load_settings().llm
        fresh = make_model_settings(
            current.reasoning_effort,
            model_name=self.model_name,
            force_required_tool_choice=current.force_required_tool_choice,
            request_timeout=current.timeout,
            prompt_cache=current.prompt_cache,
            extra_headers=current.extra_headers,
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


def _request_token_estimate(kwargs: dict[str, Any]) -> int:
    input_value = kwargs.get("input", "")
    system = kwargs.get("system_instructions") or ""
    try:
        rendered = (
            input_value if isinstance(input_value, str) else json.dumps(input_value, default=str)
        )
    except (TypeError, ValueError):
        rendered = str(input_value)
    # A model-neutral four-bytes-per-token estimate is appropriate for
    # admission control; exact provider usage replaces it after the response.
    return max(1, len(f"{system}\n{rendered}".encode()) // 4)


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
