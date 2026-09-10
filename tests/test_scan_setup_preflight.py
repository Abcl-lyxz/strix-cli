from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.model_settings import ModelSettings

from strix.config import models
from strix.core import inputs
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


def _install_model(monkeypatch: pytest.MonkeyPatch, model: Any) -> None:
    provider = SimpleNamespace(get_model=lambda _name: model)
    monkeypatch.setattr(models, "StrixProvider", lambda: provider)
    monkeypatch.setattr(models, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(inputs, "make_model_settings", lambda *_args, **_kwargs: ModelSettings())


@pytest.mark.asyncio
async def test_preflight_matches_streaming_runtime_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _RecordingModel()
    _install_model(monkeypatch, model)

    await preflight_model_connection(
        "openai/example",
        settings=cast("Any", _settings(disable_streaming=False)),
    )

    assert model.streaming_calls == 1
    assert model.non_streaming_calls == 0


@pytest.mark.asyncio
async def test_preflight_honors_disabled_streaming(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _RecordingModel()
    _install_model(monkeypatch, model)

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

    _install_model(monkeypatch, StalledModel())

    with pytest.raises(TimeoutError, match=r"model connection check timed out after 0\.01s"):
        await preflight_model_connection(
            "openai/example",
            settings=cast("Any", _settings(disable_streaming=False, timeout=0.01)),
        )
