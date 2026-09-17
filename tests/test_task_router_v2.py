from __future__ import annotations

import asyncio
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing

from strix.domain.routes import RouteConfig
from strix.routing import AllRoutesUnavailableError, RoutePool, RoutingRequest


if TYPE_CHECKING:
    from collections.abc import Iterator


class _CapturedProvider:
    def __init__(self, label: str, *, blocked: bool = False) -> None:
        self.label = label
        self.started = threading.Event()
        self.release = threading.Event()
        if not blocked:
            self.release.set()
        self.requests: list[dict[str, Any]] = []


@contextmanager
def _provider_server(provider: _CapturedProvider) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            provider.requests.append(payload)
            provider.started.set()
            provider.release.wait(timeout=5)
            body = json.dumps(
                {
                    "id": f"chatcmpl-{provider.label}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": payload.get("model", ""),
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": provider.label},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }
            ).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        provider.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request_kwargs(message: str) -> dict[str, Any]:
    return {
        "system_instructions": "test",
        "input": message,
        "model_settings": ModelSettings(),
        "tools": [],
        "output_schema": None,
        "handoffs": [],
        "tracing": ModelTracing.DISABLED,
        "previous_response_id": None,
        "conversation_id": None,
        "prompt": None,
    }


def _route(name: str, **values: Any) -> RouteConfig:
    defaults: dict[str, Any] = {
        "name": name,
        "model": f"fixture/{name}",
        "quality_tier": "strong",
        "context_window_tokens": 64_000,
        "max_output_tokens": 8_192,
        "supports_tools": True,
        "supports_vision": False,
        "supports_reasoning": False,
        "metadata_confidence": "verified",
        "input_cost_per_million": 1.0,
        "output_cost_per_million": 1.0,
    }
    defaults.update(values)
    return RouteConfig(**defaults)


async def _decision(routes: list[RouteConfig], request: RoutingRequest) -> str:
    pool = RoutePool(routes, wait_timeout=0.1, model_factory=lambda *_args: object())
    state = await pool._acquire(request=request)
    await pool._release(state)
    return state.config.name


@pytest.mark.asyncio
async def test_router_selects_different_models_for_task_profiles() -> None:
    routes = [
        _route("recon", input_cost_per_million=0.1, output_cost_per_million=0.1),
        _route("coding", supports_reasoning=True),
        _route("long", context_window_tokens=1_000_000),
        _route("vision", supports_vision=True),
    ]

    assert await _decision(routes, RoutingRequest(task_kind="recon", requires_tools=True)) == (
        "recon"
    )
    assert (
        await _decision(
            routes,
            RoutingRequest(task_kind="coding", requires_tools=True, prefers_reasoning=True),
        )
        == "coding"
    )
    assert await _decision(routes, RoutingRequest(task_kind="long_context")) == "long"
    assert (
        await _decision(
            routes,
            RoutingRequest(task_kind="vision", requires_vision=True),
        )
        == "vision"
    )


@pytest.mark.asyncio
async def test_unverified_metadata_is_ineligible_under_strict_policy() -> None:
    route = _route("uncertain", metadata_confidence="unknown")
    pool = RoutePool(
        [route],
        wait_timeout=0.01,
        allow_unknown_capabilities=False,
        model_factory=lambda *_args: object(),
    )
    with pytest.raises(AllRoutesUnavailableError):
        await pool._acquire(request=RoutingRequest(requires_tools=True))


class _ResponseModel:
    def __init__(self, label: str, *, gate: asyncio.Event | None = None) -> None:
        self.label = label
        self.gate = gate
        self.started = asyncio.Event()
        self.calls = 0

    async def get_response(self, **_kwargs: Any) -> Any:
        self.calls += 1
        self.started.set()
        if self.gate is not None:
            await self.gate.wait()
        return SimpleNamespace(usage=None, label=self.label)


@pytest.mark.asyncio
async def test_revision_switch_affects_next_request_not_in_flight_request() -> None:
    release_old = asyncio.Event()
    old_model = _ResponseModel("old", gate=release_old)
    new_model = _ResponseModel("new")
    revision = {"value": 1}
    routes = {1: _route("selected", connection_revision=1)}
    routes[2] = _route(
        "selected",
        model="fixture/new-model",
        connection_revision=2,
    )

    def factory(route: RouteConfig, *_args: Any) -> _ResponseModel:
        return old_model if route.connection_revision == 1 else new_model

    pool = RoutePool(
        [routes[1]],
        wait_timeout=0.1,
        model_factory=factory,
        route_reloader=lambda: (revision["value"], [routes[revision["value"]]]),
    )
    first_task = asyncio.create_task(pool.get_response(input="first"))
    await old_model.started.wait()
    revision["value"] = 2
    release_old.set()
    first = await first_task
    second = await pool.get_response(input="second")

    assert first.label == "old"
    assert second.label == "new"
    assert old_model.calls == new_model.calls == 1


@pytest.mark.asyncio
async def test_revision_switch_changes_the_next_captured_http_provider_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the real OpenAI-compatible client, not a model-factory stub."""
    first_provider = _CapturedProvider("first", blocked=True)
    second_provider = _CapturedProvider("second")
    monkeypatch.setenv("STRIX_V2_SWITCH_TEST_KEY", "test-key")
    with (
        _provider_server(first_provider) as first_url,
        _provider_server(second_provider) as second_url,
    ):
        revision = {"value": 1}
        routes = {
            1: _route(
                "live",
                model="openai/provider-a-model",
                base_url=first_url,
                api_key_env="STRIX_V2_SWITCH_TEST_KEY",
                connection_revision=1,
            ),
            2: _route(
                "live",
                model="openai/provider-b-model",
                base_url=second_url,
                api_key_env="STRIX_V2_SWITCH_TEST_KEY",
                connection_revision=2,
            ),
        }
        pool = RoutePool(
            [routes[1]],
            wait_timeout=2,
            route_reloader=lambda: (revision["value"], [routes[revision["value"]]]),
        )

        first_call = asyncio.create_task(pool.get_response(**_request_kwargs("first request")))
        assert await asyncio.to_thread(first_provider.started.wait, 5)
        revision["value"] = 2
        first_provider.release.set()
        await first_call
        await pool.get_response(**_request_kwargs("second request"))

    assert [request["model"] for request in first_provider.requests] == ["provider-a-model"]
    assert [request["model"] for request in second_provider.requests] == ["provider-b-model"]


class _FailingModel:
    def __init__(self) -> None:
        self.calls = 0

    async def get_response(self, **_kwargs: Any) -> Any:
        self.calls += 1
        raise TimeoutError("provider unavailable")


@pytest.mark.asyncio
async def test_logical_turn_never_exceeds_three_distinct_provider_attempts() -> None:
    routes = [_route(f"route-{index}") for index in range(4)]
    models = {route.name: _FailingModel() for route in routes}
    pool = RoutePool(
        routes,
        wait_timeout=0.1,
        max_attempts_per_turn=3,
        max_retry_input_multiplier=2.0,
        model_factory=lambda route, *_args: models[route.name],
    )

    with pytest.raises(AllRoutesUnavailableError, match="after 3 attempts"):
        await pool.get_response(input="bounded")

    assert sum(model.calls for model in models.values()) == 3
