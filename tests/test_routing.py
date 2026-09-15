"""Deterministic fault-injection coverage for the shared route pool."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from types import SimpleNamespace
from typing import Any

import pytest
from agents.model_settings import ModelSettings
from agents.retry import ModelRetrySettings

from strix import routing
from strix.routing import (
    AllRoutesUnavailableError,
    RouteConfig,
    RouteContextOverflowError,
    RoutePool,
    classify_route_failure,
)


class ProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.response = SimpleNamespace(
            headers={"Retry-After": retry_after} if retry_after is not None else {}
        )
        super().__init__(message)


def _response() -> Any:
    return SimpleNamespace(
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        output=[],
    )


class FakeModel:
    def __init__(
        self,
        outcomes: list[Any] | None = None,
        *,
        delay: float = 0,
        active: dict[str, int] | None = None,
        maximum: dict[str, int] | None = None,
        name: str = "",
    ) -> None:
        self.outcomes = deque(outcomes or [_response()])
        self.delay = delay
        self.active = active
        self.maximum = maximum
        self.name = name
        self.calls = 0
        self.last_kwargs: dict[str, Any] = {}

    async def close(self) -> None:
        return None

    async def get_response(self, **_kwargs: Any) -> Any:
        self.last_kwargs = _kwargs
        self.calls += 1
        if self.active is not None and self.maximum is not None:
            self.active[self.name] += 1
            self.maximum[self.name] = max(self.maximum[self.name], self.active[self.name])
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            outcome = self.outcomes.popleft() if len(self.outcomes) > 1 else self.outcomes[0]
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        finally:
            if self.active is not None:
                self.active[self.name] -= 1

    async def stream_response(self, **_kwargs: Any) -> Any:
        self.calls += 1
        outcome = self.outcomes.popleft() if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, list):
            for event in outcome:
                if isinstance(event, BaseException):
                    raise event
                yield event
            return
        if isinstance(outcome, BaseException):
            raise outcome
        yield outcome


def _pool(
    routes: list[RouteConfig],
    models: dict[str, FakeModel],
    *,
    wait_timeout: float | None = None,
    stream_idle_timeout: float = 300.0,
) -> RoutePool:
    return RoutePool(
        routes,
        wait_timeout=wait_timeout,
        stream_idle_timeout=stream_idle_timeout,
        model_factory=lambda route, _key, _headers: models[route.name],
    )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProviderError("rate limited", status_code=429), "transient"),
        (TimeoutError("late"), "transient"),
        (ConnectionError("offline"), "transient"),
        (ProviderError("server", status_code=501), "transient"),
        (ProviderError("unauthorized", status_code=401), "authentication"),
        (ProviderError("payment", status_code=402), "authentication"),
        (ProviderError("maximum context length exceeded", status_code=400), "context"),
        (ProviderError("unsupported tool schema", status_code=400), "incompatible"),
        (
            ProviderError("model_not_found: no available channel for model", status_code=503),
            "incompatible",
        ),
        (ProviderError("content policy refusal", status_code=400), "policy"),
        (ProviderError("bad input", status_code=400), "fatal"),
    ],
)
def test_classify_route_failures(error: BaseException, expected: str) -> None:
    assert classify_route_failure(error) == expected


@pytest.mark.asyncio
async def test_priority_then_least_loaded_selection() -> None:
    routes = [
        RouteConfig(name="a", model="model-a", priority=1, max_concurrency=2),
        RouteConfig(name="b", model="model-b", priority=1, max_concurrency=2),
        RouteConfig(name="fallback", model="model-c", priority=2),
    ]
    pool = _pool(routes, {route.name: FakeModel() for route in routes})

    first = await pool._acquire(input_tokens=1, output_tokens=1)
    second = await pool._acquire(input_tokens=1, output_tokens=1)
    third = await pool._acquire(input_tokens=1, output_tokens=1)

    assert [first.config.name, second.config.name, third.config.name] == ["a", "b", "a"]
    await pool._release(first)
    await pool._release(second)
    await pool._release(third)


@pytest.mark.asyncio
async def test_transient_failure_honors_cooldown_and_fails_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routing, "full_jitter_delay", lambda *_args, **_kwargs: 2.5)
    primary = FakeModel([ProviderError("busy", status_code=429, retry_after="2")])
    backup = FakeModel([_response()])
    routes = [
        RouteConfig(name="primary", model="model-a", priority=1),
        RouteConfig(name="backup", model="model-b", priority=2),
    ]
    pool = _pool(routes, {"primary": primary, "backup": backup})

    response = await pool.get_response(input="hello")

    assert response._strix_route_name == "backup"
    assert primary.calls == backup.calls == 1
    assert pool.states["primary"].cooldown_until - time.monotonic() > 2


@pytest.mark.asyncio
async def test_headless_route_wait_uses_one_bounded_outage_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routing, "full_jitter_delay", lambda *_args, **_kwargs: 0.02)
    model = FakeModel([ProviderError("busy", status_code=503), _response()])
    route = RouteConfig(name="only", model="model-a")
    pool = _pool([route], {"only": model}, wait_timeout=0.3)

    response = await pool.get_response(input="hello")

    assert response._strix_route_name == "only"
    assert model.calls == 2


@pytest.mark.asyncio
async def test_headless_outage_exits_after_configured_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routing, "full_jitter_delay", lambda *_args, **_kwargs: 0.01)
    model = FakeModel([ProviderError("busy", status_code=503)])
    pool = _pool(
        [RouteConfig(name="only", model="model-a")],
        {"only": model},
        wait_timeout=0.06,
    )
    with pytest.raises(AllRoutesUnavailableError, match="0s"):
        await asyncio.wait_for(pool.get_response(input="hello"), timeout=2.0)

    assert model.calls >= 1


@pytest.mark.asyncio
async def test_interactive_outage_parks_instead_of_blocking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routing, "full_jitter_delay", lambda *_args, **_kwargs: 60.0)
    model = FakeModel([ProviderError("busy", status_code=503)])
    pool = _pool([RouteConfig(name="only", model="model-a")], {"only": model})

    with pytest.raises(AllRoutesUnavailableError):
        await pool.get_response(input="hello")


@pytest.mark.asyncio
async def test_authentication_failure_blocks_only_affected_route() -> None:
    primary = FakeModel([ProviderError("bad key", status_code=401)])
    backup = FakeModel([_response()])
    routes = [
        RouteConfig(name="primary", model="model-a", priority=1),
        RouteConfig(name="backup", model="model-b", priority=2),
    ]
    pool = _pool(routes, {"primary": primary, "backup": backup})

    await pool.get_response(input="hello")

    assert pool.states["primary"].blocked_reason is not None
    assert pool.states["backup"].successful_turns == 1


@pytest.mark.asyncio
async def test_removed_model_is_not_retried_and_has_selection_guidance() -> None:
    model = FakeModel(
        [ProviderError("model_not_found: no available channel for model", status_code=503)]
    )
    pool = _pool(
        [RouteConfig(name="primary", model="openai/removed-model")],
        {"primary": model},
    )

    with pytest.raises(AllRoutesUnavailableError, match=r"/models"):
        await pool.get_response(input="hello")

    assert model.calls == 1
    assert pool.states["primary"].disabled_for_run is True


@pytest.mark.asyncio
async def test_configuration_revision_recovers_blocked_route() -> None:
    model = FakeModel([ProviderError("bad key", status_code=401), _response()])
    route = RouteConfig(name="primary", model="model-a")
    revision = {"value": 1}
    pool = RoutePool(
        [route],
        wait_timeout=None,
        model_factory=lambda _route, _key, _headers: model,
        route_reloader=lambda: (revision["value"], [route]),
    )

    with pytest.raises(AllRoutesUnavailableError):
        await pool.get_response(input="hello")
    assert pool.states["primary"].blocked_reason is not None

    revision["value"] = 2
    await asyncio.wait_for(pool.wait_until_available(requires_tools=False), timeout=1)
    response = await pool.get_response(input="hello")

    assert response._strix_route_name == "primary"
    assert pool.states["primary"].blocked_reason is None


@pytest.mark.asyncio
async def test_context_overflow_does_not_reduce_route_health() -> None:
    error = ProviderError("context length exceeded", status_code=400)
    pool = _pool(
        [RouteConfig(name="only", model="model-a")],
        {"only": FakeModel([error])},
    )

    with pytest.raises(ProviderError, match="context"):
        await pool.get_response(input="hello")

    state = pool.states["only"]
    assert state.blocked_reason is None
    assert state.disabled_for_run is False
    assert state.cooldown_until == 0


@pytest.mark.asyncio
async def test_capacity_overflow_is_distinct_from_route_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routing, "context_window", lambda _model: 16)
    pool = _pool(
        [RouteConfig(name="only", model="tiny")],
        {"only": FakeModel()},
    )

    with pytest.raises(RouteContextOverflowError):
        await pool.get_response(input="x" * 100)

    assert pool.states["only"].failed_turns == 0


@pytest.mark.asyncio
async def test_policy_refusal_is_not_sent_to_another_route() -> None:
    primary = FakeModel([ProviderError("content policy refusal", status_code=400)])
    backup = FakeModel([_response()])
    routes = [
        RouteConfig(name="primary", model="model-a", priority=1),
        RouteConfig(name="backup", model="model-b", priority=2),
    ]
    pool = _pool(routes, {"primary": primary, "backup": backup})

    with pytest.raises(ProviderError, match="policy"):
        await pool.get_response(input="hello")

    assert backup.calls == 0


@pytest.mark.asyncio
async def test_partially_streamed_turn_is_never_replayed_to_fallback() -> None:
    event = SimpleNamespace(response=None)
    primary = FakeModel([[event, ProviderError("stream reset", status_code=503)]])
    backup = FakeModel([[event]])
    routes = [
        RouteConfig(name="primary", model="model-a", priority=1),
        RouteConfig(name="backup", model="model-b", priority=2),
    ]
    pool = _pool(routes, {"primary": primary, "backup": backup})

    seen = []
    with pytest.raises(ProviderError, match="stream reset"):
        async for item in pool.stream_response(input="hello"):
            seen.append(item)  # noqa: PERF401 - retain partial output before injected failure

    assert seen == [event]
    assert backup.calls == 0


@pytest.mark.asyncio
async def test_idle_stream_is_recovered_before_any_side_effect_is_emitted() -> None:
    event = SimpleNamespace(response=None)

    class IdleModel(FakeModel):
        async def stream_response(self, **_kwargs: Any) -> Any:
            self.calls += 1
            await asyncio.sleep(0.2)
            yield event

    primary = IdleModel()
    backup = FakeModel([[event]])
    routes = [
        RouteConfig(name="primary", model="model-a", priority=1),
        RouteConfig(name="backup", model="model-b", priority=2),
    ]
    pool = _pool(
        routes,
        {"primary": primary, "backup": backup},
        stream_idle_timeout=0.01,
    )

    seen = [item async for item in pool.stream_response(input="hello")]

    assert seen == [event]
    assert primary.calls == backup.calls == 1
    assert pool.states["primary"].failed_turns == 1


@pytest.mark.asyncio
async def test_twelve_agents_respect_per_route_concurrency() -> None:
    active: dict[str, int] = defaultdict(int)
    maximum: dict[str, int] = defaultdict(int)
    routes = [
        RouteConfig(name="a", model="model-a", max_concurrency=2),
        RouteConfig(name="b", model="model-b", max_concurrency=3),
    ]
    models = {
        route.name: FakeModel(
            delay=0.01,
            active=active,
            maximum=maximum,
            name=route.name,
        )
        for route in routes
    }
    pool = _pool(routes, models)

    responses = await asyncio.gather(*(pool.get_response(input=str(i)) for i in range(12)))

    assert len(responses) == 12
    assert maximum["a"] <= 2
    assert maximum["b"] <= 3
    assert sum(model.calls for model in models.values()) == 12


@pytest.mark.asyncio
async def test_routed_call_disables_nested_sdk_retry() -> None:
    model = FakeModel()
    pool = _pool([RouteConfig(name="only", model="model-a")], {"only": model})

    await pool.get_response(
        input="hello",
        model_settings=ModelSettings(retry=ModelRetrySettings(max_retries=3)),
    )

    assert model.last_kwargs["model_settings"].retry is None


@pytest.mark.asyncio
async def test_route_known_not_to_support_tools_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        routing,
        "_explicitly_lacks_tool_support",
        lambda model: model == "text-only",
    )
    text_only = FakeModel()
    capable = FakeModel()
    routes = [
        RouteConfig(name="text", model="text-only", priority=1),
        RouteConfig(name="tools", model="tool-model", priority=2),
    ]
    pool = _pool(routes, {"text": text_only, "tools": capable})

    response = await pool.get_response(input="hello", tools=[object()])

    assert response._strix_route_name == "tools"
    assert text_only.calls == 0
    assert pool.states["text"].disabled_for_run is True


@pytest.mark.asyncio
async def test_half_open_circuit_allows_exactly_one_probe() -> None:
    active: dict[str, int] = defaultdict(int)
    maximum: dict[str, int] = defaultdict(int)
    model = FakeModel(delay=0.04, active=active, maximum=maximum, name="only")
    pool = _pool(
        [RouteConfig(name="only", model="model-a", max_concurrency=4)],
        {"only": model},
        wait_timeout=0.5,
    )
    state = pool.states["only"]
    state.consecutive_failures = 1
    state.effective_concurrency = 1

    calls = [asyncio.create_task(pool.get_response(input=str(index))) for index in range(3)]
    await asyncio.sleep(0.01)

    assert state.circuit_state(time.monotonic()) == "half_open"
    assert state.probe_in_flight is True
    assert model.calls == 1

    await asyncio.gather(*calls)
    assert maximum["only"] <= 2
    assert state.circuit_state(time.monotonic()) == "closed"


@pytest.mark.asyncio
async def test_context_ceiling_and_attempted_usage_survive_restart(tmp_path: Any) -> None:
    health_path = tmp_path / ".state" / "routes.json"
    route = RouteConfig(name="only", model="model-a", context_window_tokens=100_000)
    pool = RoutePool(
        [route],
        wait_timeout=None,
        health_path=health_path,
        model_factory=lambda _route, _key, _headers: FakeModel(
            [ProviderError("maximum context length exceeded", status_code=400)]
        ),
    )

    with pytest.raises(ProviderError, match="context"):
        await pool.get_response(input="x" * 20_000)

    original = pool.states["only"]
    assert original.learned_context_window is not None
    assert original.attempted_input_tokens > 0
    assert original.retry_waste_tokens == original.attempted_input_tokens

    restored = RoutePool(
        [route],
        wait_timeout=None,
        health_path=health_path,
        model_factory=lambda _route, _key, _headers: FakeModel(),
    ).states["only"]
    assert restored.learned_context_window == original.learned_context_window
    assert restored.attempted_input_tokens == original.attempted_input_tokens
    assert restored.retry_waste_tokens == original.retry_waste_tokens
