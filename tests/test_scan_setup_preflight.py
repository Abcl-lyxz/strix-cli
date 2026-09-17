from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.model_settings import ModelSettings

from strix.config import models
from strix.config.app_config import AppConfig
from strix.core import inputs
from strix.domain.routes import RouteConfig
from strix.interface.scan_setup import preflight_model_connection


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class _RecordingModel:
    def __init__(self) -> None:
        self.streaming_calls = 0
        self.non_streaming_calls = 0

    async def stream_response(self, **_kwargs: Any) -> AsyncIterator[object]:
        self.streaming_calls += 1
        yield object()

    async def get_response(self, **_kwargs: Any) -> object:
        self.non_streaming_calls += 1
        return object()


def _settings(*, disable_streaming: bool, timeout: float = 5) -> Any:
    return SimpleNamespace(
        llm=SimpleNamespace(
            timeout=timeout,
            extra_headers=None,
            disable_streaming=disable_streaming,
        )
    )


def _install_model(
    monkeypatch: pytest.MonkeyPatch,
    model: Any,
    *,
    streaming: bool = True,
    timeout: int = 5,
) -> None:
    provider = SimpleNamespace(get_model=lambda _name: model)
    monkeypatch.setattr(models, "StrixProvider", lambda *_args, **_kwargs: provider)
    monkeypatch.setattr(inputs, "make_model_settings", lambda *_args, **_kwargs: ModelSettings())
    config = AppConfig(ui={"streaming_enabled": streaming, "llm_timeout_seconds": timeout})
    monkeypatch.setattr(
        "strix.config.app_config.get_config_service",
        lambda: SimpleNamespace(load=lambda: config),
    )
    monkeypatch.setattr(
        "strix.config.runtime_routes.load_app_routes",
        lambda: [
            RouteConfig(
                name="test",
                model="openai/example",
                supports_tools=True,
                context_window_tokens=128_000,
                metadata_confidence="verified",
            )
        ],
    )


@pytest.mark.asyncio
async def test_preflight_matches_streaming_runtime_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _RecordingModel()
    _install_model(monkeypatch, model, streaming=True)

    await preflight_model_connection(
        "openai/example",
        settings=cast("Any", _settings(disable_streaming=False)),
    )

    assert model.streaming_calls == 1
    assert model.non_streaming_calls == 0


@pytest.mark.asyncio
async def test_preflight_honors_disabled_streaming(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _RecordingModel()
    _install_model(monkeypatch, model, streaming=False)

    await preflight_model_connection(
        "openai/example",
        settings=cast("Any", _settings(disable_streaming=True)),
    )

    assert model.streaming_calls == 0
    assert model.non_streaming_calls == 1


@pytest.mark.asyncio
async def test_preflight_timeout_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    class StalledModel(_RecordingModel):
        async def stream_response(self, **_kwargs: Any) -> AsyncIterator[object]:
            await asyncio.sleep(1)
            yield object()

    _install_model(monkeypatch, StalledModel(), streaming=True, timeout=1)

    with pytest.raises(TimeoutError, match=r"model connection check timed out after 1s"):
        await preflight_model_connection(
            "openai/example",
            settings=cast("Any", _settings(disable_streaming=False, timeout=1)),
        )
