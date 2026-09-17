"""Failure injection for the local workspace, with no targets or paid model calls."""

from __future__ import annotations

import asyncio
import json
import threading
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import httpx
import litellm
import pytest
from agents import Agent, RunConfig, function_tool
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.retry import ModelRetryNormalizedError, RetryPolicyContext
from openai import AsyncOpenAI

from strix.config.app_config import get_config_service
from strix.config.models import (
    DEFAULT_MODEL_RETRY,
    _configure_litellm_compatibility,
    _NonStreamingModel,
    _TurnGuardModel,
)
from strix.config.runtime_routes import load_app_routes
from strix.core import agents, execution
from strix.core.agents import AgentCoordinator
from strix.core.ownership import RunLease
from strix.core.sessions import open_agent_session
from strix.interface.application_runtime import WorkspaceRuntime
from strix.interface.cli_args import parse_arguments
from strix.interface.output import WorkspaceOutput
from strix.interface.viewer.server import authorized_url, serve
from strix.interface.viewer.transcript import read_run_summary
from strix.llm.tool_arguments import parse_tool_arguments
from strix.providers import get_provider_registry
from strix.security import get_secret_store
from strix.utils.atomic import atomic_write_text


if TYPE_CHECKING:
    from pathlib import Path


def test_dependency_analytics_are_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(litellm, "telemetry", True)
    _configure_litellm_compatibility()
    assert litellm.telemetry is False


@pytest.mark.asyncio
async def test_extended_synthetic_scan_preserves_completed_tools_across_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """64 real SDK turns, 32 injected malformed responses, checkpoint and resume."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(execution, "_compact_session", AsyncMock(return_value=False))
    calls = 0
    executed: list[int] = []
    repaired_results: list[str] = []

    @function_tool
    def record_step(step: int) -> str:
        """Record one synthetic action."""
        assert step not in executed, "A completed action was replayed"
        executed.append(step)
        return f"completed-{step}"

    def gateway(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        payload = json.loads(request.content)
        # Every request must be safe, including the deliberately broken old session.
        for message in payload["messages"]:
            for call in message.get("tool_calls", []):
                parse_tool_arguments(call["function"]["arguments"])
        step, phase = divmod(calls, 3)
        calls += 1
        if phase == 1:
            return httpx.Response(
                400,
                json={
                    "error": {
                        "message": "Assistant tool call redacted.arguments must be valid JSON.",
                        "type": "bad_response_status_code",
                    }
                },
            )
        if phase == 2:
            assert any(
                m.get("role") == "tool" and f"completed-{step}" in str(m.get("content"))
                for m in payload["messages"]
            ), "A completed result was lost during recovery"
            repaired_results.append(f"completed-{step}")
        message = {"role": "assistant", "content": "Synthetic turn complete"}
        if phase == 0:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call-{step}",
                        "type": "function",
                        "function": {
                            "name": "record_step",
                            "arguments": json.dumps({"step": step}),
                        },
                    }
                ],
            }
        return httpx.Response(
            200,
            json={
                "id": f"response-{calls}",
                "object": "chat.completion",
                "created": 0,
                "model": "synthetic",
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if phase == 0 else "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            },
        )

    client = AsyncOpenAI(
        api_key="synthetic-only",
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(gateway)),
    )
    model = _TurnGuardModel(
        _NonStreamingModel(OpenAIChatCompletionsModel("synthetic", client)),
        max_tool_calls_per_turn=4,
        stream_idle_timeout=5,
    )
    agent = Agent(name="synthetic", model=model, tools=[record_step])
    session = open_agent_session("root", tmp_path / "agents.db")
    await session.add_items(
        [
            {
                "type": "function_call",
                "call_id": "old-broken",
                "name": "record_step",
                "arguments": "{broken",
            },
            {
                "type": "function_call_output",
                "call_id": "old-broken",
                "output": "invalid arguments; no action",
            },
        ]
    )
    coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(tmp_path / "agents.json")
    await coordinator.register("root", "synthetic", parent_id=None)
    try:
        for turn in range(32):
            if turn == 16:
                session.close()
                session = open_agent_session("root", tmp_path / "agents.db")
            result = await execution._run_cycle(
                agent,
                coordinator,
                "root",
                input_data=f"Synthetic turn {turn}",
                run_config=RunConfig(tracing_disabled=True),
                context={"scan_id": "synthetic"},
                max_turns=5,
                session=session,
                interactive=False,
                event_sink=None,
                hooks=None,
            )
            assert result.final_output == "Synthetic turn complete"
            assert len(await session.get_items()) < 12 * (turn + 1) + 10
        assert executed == list(range(32))
        assert len(repaired_results) == 32 and calls == 96
        assert json.loads((tmp_path / "agents.json").read_text())["statuses"]["root"] == "running"
    finally:
        session.close()
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message", ["billing quota exceeded", "invalid api key", "arguments must be valid JSON"]
)
async def test_sdk_retry_does_not_retry_permanent_failures_even_with_http_429(message: str) -> None:
    context = RetryPolicyContext(
        error=RuntimeError(message),
        attempt=1,
        max_retries=3,
        stream=True,
        normalized=ModelRetryNormalizedError(status_code=429),
        provider_advice=None,
    )
    assert await DEFAULT_MODEL_RETRY.policy(context) is False


@pytest.mark.asyncio
async def test_cancelled_snapshot_flushes_before_next_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(tmp_path / "agents.json")
    entered, release = threading.Event(), threading.Event()
    original = agents.atomic_write_text

    def blocked(path: Path, value: str) -> None:
        entered.set()
        release.wait(5)
        original(path, value)

    monkeypatch.setattr(agents, "atomic_write_text", blocked)
    task = asyncio.create_task(coordinator.register("root", "test", parent_id=None))
    await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await coordinator.set_status("root", "stopped")
    assert json.loads((tmp_path / "agents.json").read_text())["statuses"]["root"] == "stopped"


def test_abandoned_run_is_interrupted_and_live_lease_is_respected(tmp_path: Path) -> None:
    atomic_write_text(tmp_path / "run.json", '{"status":"running"}')
    lease = RunLease(tmp_path)
    lease.acquire()
    assert read_run_summary(tmp_path)["status"] == "running"
    lease.close()
    assert read_run_summary(tmp_path)["status"] == "interrupted"


def test_environment_model_cannot_override_empty_v3_router(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/old")
    with pytest.raises(ValueError, match="No enabled Strix v2 models"):
        load_app_routes()
    assert get_config_service().load().connections == {}


def test_connection_is_saved_without_requiring_a_model() -> None:
    adapter = get_provider_registry().adapter("custom")
    connection = adapter.connect(
        {
            "connection_id": "gateway",
            "base_url": "https://gateway.invalid/v1",
            "api_key": "fixture-key",
        }
    )
    config = get_config_service().load()
    assert connection.id == "gateway"
    assert config.connections["gateway"].options["base_url"] == ("https://gateway.invalid/v1")
    assert config.models == {}


def test_connection_key_rotation_deletes_the_old_reference() -> None:
    adapter = get_provider_registry().adapter("openrouter")
    first = adapter.connect({"connection_id": "gateway", "api_key": "fixture-original"})
    second = adapter.connect({"connection_id": "gateway", "api_key": "fixture-replacement"})
    assert first.secret_ref != second.secret_ref
    assert get_secret_store().get(first.secret_ref or "") is None
    assert get_secret_store().get(second.secret_ref or "") == "fixture-replacement"


@pytest.mark.asyncio
async def test_connected_provider_is_visible_without_selecting_a_global_model() -> None:
    runtime = WorkspaceRuntime(parse_arguments([]))
    try:
        await runtime.controller.workspace.dispatch(
            "providers.connect",
            {"provider_id": "openrouter", "api_key": "fixture-key"},
            "session-connection",
        )
        state = runtime.controller.snapshot()
        assert state["model"] == ""
        assert state["api_key_configured"] is True
        assert get_config_service().load().models == {}
    finally:
        await runtime.quit()
        runtime.controller.close()


@pytest.mark.asyncio
async def test_target_chip_removal_uses_identity_and_removes_target_attachments(
    tmp_path: Path,
) -> None:
    runtime = WorkspaceRuntime(parse_arguments([]))
    controller = runtime.controller
    try:
        long_url = "https://example.invalid/" + "long-segment/" * 30
        await controller.handle("setup.add_target", {"target": long_url})
        state = controller.snapshot()
        assert state["targets"][0] != long_url
        await controller.handle("setup.remove_target", {"target_id": state["target_ids"][0]})
        assert not controller.targets
        file = tmp_path / "target.bin"
        file.write_bytes(b"\0fixture")
        await controller.workspace.dispatch(
            "attachments.add", {"path": str(file), "role": "target"}
        )
        await controller.handle("setup.remove_target", {"target": str(file)})
        assert not controller.workspace.attachments
        assert not runtime.args.workspace_files
        assert not runtime.args.targets_info
    finally:
        await runtime.quit()
        controller.close()


@pytest.mark.asyncio
async def test_followup_attachment_staging_failure_does_not_accept_or_lose_draft(
    tmp_path: Path,
) -> None:
    runtime = WorkspaceRuntime(parse_arguments([]))
    runtime.controller.setup_mode = False
    runtime.controller.scan_started = True
    runtime.args.run_name = "not-started"
    file = tmp_path / "binary.bin"
    file.write_bytes(b"\0\xff")
    with pytest.raises(RuntimeError, match="Sandbox is not ready"):
        await runtime.controller.workspace.dispatch(
            "attachments.add", {"path": str(file)}, "attachment"
        )
    assert runtime.controller.workspace.attachments == []
    assert "attachment" not in runtime.controller.workspace.results
    runtime.controller.close()


def test_output_redacts_secrets_without_losing_long_lines() -> None:
    emitted = []
    stream = WorkspaceOutput(emitted.append)
    stream.write("x" * 8001 + "\n")
    assert "".join(emitted) == "x" * 8001
    stream.write("viewer?token=private-token\n")
    assert "private-token" not in emitted[-1]


def test_authenticated_viewer_remains_read_only(tmp_path: Path) -> None:
    httpd, url, token = serve(tmp_path / "workspace", open_browser=False)
    try:
        with httpx.Client() as client:
            assert client.post(url + "/api/attachments/upload", content=b"x").status_code == 403
            client.get(authorized_url(url, token))
            assert (
                client.post(
                    url + "/api/attachments/upload",
                    headers={"Origin": "https://foreign.invalid"},
                    content=b"x",
                ).status_code
                == 403
            )
            response = client.post(
                url + "/api/attachments/upload",
                headers={"X-File-Name": "fixture.bin"},
                content=b"\0binary\xff",
            )
            assert response.status_code == 405
            assert response.json() == {"error": "viewer is read-only"}
            assert (
                client.post(
                    url + "/api/attachments/upload",
                    headers={"X-File-Name": "..%2Fbad"},
                    content=b"x",
                ).status_code
                == 405
            )
    finally:
        httpd.shutdown()
        httpd.server_close()
