from __future__ import annotations

import argparse
import asyncio
import os
import shutil
from pathlib import Path

import pytest

from strix.config import apply_config_override, loader
from strix.config.settings import DEFAULT_MAX_AGENTS, DEFAULT_MAX_TURNS
from strix.interface.tui.backend.controller import TuiController


class _SendingCoordinator:
    def __init__(self, delivered: bool = True) -> None:
        self.delivered = delivered
        self.messages: list[tuple[str, dict[str, object]]] = []

    async def send(self, agent_id: str, message: dict[str, object]) -> bool:
        self.messages.append((agent_id, message))
        return self.delivered


def args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True,
        targets_info=[],
        instruction=None,
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=DEFAULT_MAX_TURNS,
        max_agents=DEFAULT_MAX_AGENTS,
        scope_mode="auto",
        diff_base=None,
        local_sources=[],
        diff_scope={"active": False},
        user_explicit_instruction=None,
        run_name=None,
    )


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "STRIX_LLM",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LLM_API_KEY",
        "LLM_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "OLLAMA_API_BASE",
        "AZURE_API_KEY",
        "AZURE_API_BASE",
        "AZURE_API_VERSION",
        "STRIX_REASONING_EFFORT",
        "STRIX_TELEMETRY",
        "LLM_DISABLE_STREAMING",
        "STRIX_PROMPT_CACHE",
        "LLM_TIMEOUT",
        "LLM_MAX_TOOL_CALLS_PER_TURN",
        "STRIX_MAX_CONTEXT_IMAGES",
    ):
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(key.lower(), raising=False)
    apply_config_override(tmp_path / "config.json")


@pytest.mark.asyncio
async def test_setup_state_is_serializable() -> None:
    controller = TuiController(args())
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    await controller.handle("setup.set_instruction", {"instruction": "focus on auth"})
    snapshot = controller.snapshot()
    assert snapshot["targets"] == ["https://example.com"]
    assert snapshot["instruction"] == "focus on auth"
    assert snapshot["scan_state"] == "setup"
    assert snapshot["scan_mode"] == "deep"
    assert snapshot["max_budget_usd"] is None
    assert snapshot["max_turns"] == 500
    assert snapshot["max_agents"] == DEFAULT_MAX_AGENTS
    assert snapshot["scope_mode"] == "auto"
    assert snapshot["diff_base"] is None
    assert snapshot["api_key_configured"] is False
    assert snapshot["reasoning_effort"] == "high"


@pytest.mark.asyncio
async def test_setup_instruction_preserves_multiline_whitespace() -> None:
    controller = TuiController(args())
    instruction = "  first line\nsecond line \n"

    result = await controller.handle("setup.set_instruction", {"instruction": instruction})

    assert result == {"instruction": instruction}
    assert controller.snapshot()["instruction"] == instruction


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep is not installed")
async def test_tui_find_searches_workspace_without_an_agent_turn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "module.py").write_text("value = 'ade'\n", encoding="utf-8")
    coordinator = _SendingCoordinator()
    controller = TuiController(args(), coordinator=coordinator)

    result = await controller.handle("workspace.find", {"query": "ade"})

    assert result["match_count"] == 1
    assert result["matches"][0]["path"] == "module.py"
    assert coordinator.messages == []


@pytest.mark.asyncio
async def test_tui_can_persist_model_credentials_without_exposing_the_key() -> None:
    controller = TuiController(args())

    result = await controller.handle(
        "config.update",
        {
            "model": "openrouter/openai/gpt-5.4",
            "api_key": "sk-do-not-echo",
            "api_base": "https://gateway.example/v1",
            "persist": True,
            "reasoning_effort": "medium",
        },
    )

    assert result == {
        "saved": True,
        "selected_route": "",
        "model": "openrouter/openai/gpt-5.4",
        "api_key_configured": True,
        "api_base": "https://gateway.example/v1",
        "reasoning_effort": "medium",
    }
    assert "sk-do-not-echo" not in str(result)
    snapshot = controller.snapshot()
    assert snapshot["model"] == "openrouter/openai/gpt-5.4"
    assert snapshot["api_key_configured"] is True
    assert snapshot["api_base"] == "https://gateway.example/v1"
    assert "sk-do-not-echo" not in str(snapshot)


@pytest.mark.asyncio
async def test_tui_config_supports_runtime_model_controls() -> None:
    controller = TuiController(args())

    await controller.handle(
        "config.update",
        {
            "streaming_enabled": False,
            "prompt_cache": False,
            "llm_timeout": 45,
            "max_tool_calls_per_turn": 11,
            "max_context_images": 0,
        },
    )

    snapshot = controller.snapshot()
    assert "telemetry_enabled" not in snapshot
    assert snapshot["streaming_enabled"] is False
    assert snapshot["prompt_cache"] is False
    assert snapshot["llm_timeout"] == 45
    assert snapshot["max_tool_calls_per_turn"] == 11
    assert snapshot["max_context_images"] == 0


@pytest.mark.asyncio
async def test_tui_config_rejects_credential_in_base_url() -> None:
    controller = TuiController(args())

    with pytest.raises(ValueError, match="must not contain credentials"):
        await controller.handle("config.update", {"api_base": "https://secret@example.com/v1"})


@pytest.mark.asyncio
async def test_tui_config_rejects_multiline_api_keys() -> None:
    controller = TuiController(args())

    with pytest.raises(ValueError, match="single line"):
        await controller.handle("config.update", {"api_key": "first\nsecond"})


@pytest.mark.asyncio
async def test_setup_configuration_updates_all_scan_controls() -> None:
    controller = TuiController(args())

    result = await controller.handle(
        "setup.configure",
        {
            "scan_mode": "quick",
            "max_budget_usd": 4.5,
            "max_turns": 75,
            "max_agents": 6,
            "scope_mode": "diff",
            "diff_base": "origin/main",
        },
    )

    assert result == {
        "scan_mode": "quick",
        "max_budget_usd": 4.5,
        "max_turns": 75,
        "max_agents": 6,
        "scope_mode": "diff",
        "diff_base": "origin/main",
    }
    assert controller.snapshot()["max_agents"] == 6


@pytest.mark.asyncio
async def test_setup_targets_can_be_removed_or_cleared() -> None:
    controller = TuiController(args())
    await controller.handle("setup.add_target", {"target": "https://one.example"})
    await controller.handle("setup.add_target", {"target": "https://two.example"})

    removed = await controller.handle("setup.remove_target", {"target": "https://one.example"})
    cleared = await controller.handle("setup.clear_targets", {})

    assert removed["total"] == 1
    assert cleared == {"removed": 1, "total": 0}
    assert controller.snapshot()["targets"] == []


@pytest.mark.asyncio
async def test_connections_snapshot_reflects_the_pushed_mcp_roster() -> None:
    controller = TuiController(args())
    # A run with no MCP connections carries an empty roster, so the sidebar
    # omits the panel entirely.
    assert controller.snapshot()["connections"] == []

    controller.set_mcp_connections(
        [
            {"name": "supabase", "tool_count": 3, "dead": False},
            {"name": "vercel", "tool_count": 1, "dead": True},
        ]
    )
    assert controller.snapshot()["connections"] == [
        {"name": "supabase", "tool_count": 3, "dead": False},
        {"name": "vercel", "tool_count": 1, "dead": True},
    ]


@pytest.mark.asyncio
async def test_setup_instruction_starts_from_cli_and_can_be_cleared() -> None:
    setup_args = args()
    setup_args.instruction = "  CLI instruction  "
    controller = TuiController(setup_args)

    assert controller.snapshot()["instruction"] == "CLI instruction"

    result = await controller.handle("setup.set_instruction", {"instruction": ""})

    assert result == {"instruction": ""}
    assert controller.snapshot()["instruction"] == ""


@pytest.mark.asyncio
async def test_setup_controls_reject_changes_after_start() -> None:
    controller = TuiController(args())
    controller.setup_mode = False
    controller.scan_started = True

    with pytest.raises(RuntimeError, match="can no longer be changed"):
        await controller.handle("setup.add_target", {"target": "https://example.com"})


@pytest.mark.asyncio
async def test_large_target_list_reports_truncated_snapshot_count() -> None:
    controller = TuiController(args())

    for index in range(20):
        await controller.handle("setup.add_target", {"target": f"https://target-{index}.example"})
    added = await controller.handle("setup.add_target", {"target": "https://last.example"})
    snapshot = controller.snapshot()

    assert added == {"target": "https://last.example", "total": 21}
    assert snapshot["target_count"] == 21
    # The snapshot only carries a bounded prefix of the list.
    assert len(snapshot["targets"]) == 16


def test_state_populates_model_warning_for_non_frontier_model() -> None:
    os.environ["STRIX_LLM"] = "openai/gpt-3.5-turbo"
    loader._cached = None

    warning = TuiController(args()).snapshot()["model_warning"]

    assert "openai/gpt-3.5-turbo" in warning
    assert "not a recommended frontier model" in warning


def test_setup_restores_prepared_cli_targets() -> None:
    setup_args = args()
    setup_args.targets_info = [
        {"type": "web", "details": {}, "original": "https://example.com"},
        {"type": "local_code", "details": {}, "original": "/workspace/source"},
    ]

    controller = TuiController(setup_args)

    assert controller.snapshot()["targets"] == ["https://example.com", "/workspace/source"]


@pytest.mark.asyncio
async def test_start_validates_model_before_callback() -> None:
    started = False

    async def start() -> None:
        nonlocal started
        started = True

    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    with pytest.raises(ValueError, match="No model configured"):
        await controller.handle("setup.start", {})
    assert started is False


@pytest.mark.asyncio
async def test_start_launches_with_a_configured_model() -> None:
    started = False

    async def start() -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    result = await controller.handle("setup.start", {})

    assert result == {"started": True}
    assert started is True


@pytest.mark.asyncio
async def test_start_without_target_requires_mount_consent() -> None:
    started = False

    async def start() -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)

    # Mounting the working directory is never silent.
    with pytest.raises(ValueError, match="No target set"):
        await controller.handle("setup.start", {})
    assert started is False
    assert controller.targets == []
    assert controller.workspace_mount is None


@pytest.mark.asyncio
async def test_target_less_start_enters_live_view_and_waits_for_the_mount() -> None:
    """Nothing is prepared until the live-view confirmation is answered."""
    started = False

    async def start() -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)

    result = await controller.handle("setup.start", {"mount_working_dir": True})

    assert result == {"started": True}
    # The live view is up so the prompt can be shown there, but the scan has not
    # been prepared and nothing is mounted yet.
    assert started is False
    assert controller.setup_mode is False
    assert controller.scan_state == "preparing"
    assert controller.pending_workspace_mount == str(Path.cwd())
    assert controller.workspace_mount is None
    assert controller.snapshot()["pending_mount"] == str(Path.cwd())


@pytest.mark.asyncio
async def test_confirming_the_mount_starts_the_scan_without_a_target() -> None:
    started = False

    async def start() -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": True})

    assert result == {"approved": True}
    assert started is True
    # Mounted as a workspace: the scan genuinely has no target, so the
    # instruction is the only source of truth.
    assert controller.workspace_mount == str(Path.cwd())
    assert controller.targets == []
    assert controller.scan_state == "running"
    assert controller.snapshot()["pending_mount"] == ""


@pytest.mark.asyncio
async def test_declining_the_mount_runs_without_one() -> None:
    started = 0

    async def start() -> None:
        nonlocal started
        started += 1

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": False})

    assert result == {"approved": False}
    # Declining skips the directory; it does not abandon the scan.
    assert started == 1
    assert controller.workspace_mount is None
    assert controller.pending_workspace_mount is None
    assert controller.setup_mode is False
    assert controller.scan_started is True
    assert controller.scan_state == "running"


@pytest.mark.asyncio
async def test_approving_the_mount_runs_with_it() -> None:
    started = 0

    async def start() -> None:
        nonlocal started
        started += 1

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": True})

    assert result == {"approved": True}
    assert started == 1
    assert controller.workspace_mount == str(Path.cwd())
    assert controller.scan_state == "running"


@pytest.mark.asyncio
async def test_confirm_mount_requires_a_pending_request() -> None:
    controller = TuiController(args())

    with pytest.raises(RuntimeError, match="No mount confirmation is pending"):
        await controller.handle("setup.confirm_mount", {"approved": True})


def test_snapshot_exposes_working_directory() -> None:
    controller = TuiController(args())

    assert controller.snapshot()["working_dir"] == str(Path.cwd())
    assert controller.snapshot()["pending_mount"] == ""


@pytest.mark.asyncio
async def test_user_message_updates_live_agent_projection_immediately() -> None:
    coordinator = _SendingCoordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.setup_mode = False
    controller.scan_started = True
    controller.scan_loop = asyncio.get_running_loop()
    controller.live_view.upsert_agent(
        "root",
        name="Strix",
        status="failed",
        error_message="provider rejected request",
    )

    result = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "try again"},
    )

    assert result == {"sent": True}
    assert coordinator.messages == [
        ("root", {"from": "user", "content": "try again", "type": "instruction"})
    ]
    agent = controller.live_view.agents["root"]
    assert agent["status"] == "waiting"
    assert "error_message" not in agent


@pytest.mark.asyncio
async def test_user_message_preserves_multiline_whitespace() -> None:
    coordinator = _SendingCoordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.setup_mode = False
    controller.scan_started = True
    controller.scan_loop = asyncio.get_running_loop()
    controller.live_view.upsert_agent("root", name="Strix", status="waiting")
    message = "  first line\nsecond line \n"

    await controller.handle("agent.send_message", {"agent_id": "root", "message": message})

    assert coordinator.messages == [
        ("root", {"from": "user", "content": message, "type": "instruction"})
    ]


@pytest.mark.asyncio
async def test_start_verifies_the_model_before_a_targeted_launch() -> None:
    order: list[str] = []

    async def verify() -> None:
        order.append("verify")

    async def start() -> None:
        order.append("start")

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start, on_verify=verify)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    await controller.handle("setup.start", {})

    assert order == ["verify", "start"]


@pytest.mark.asyncio
async def test_start_verifies_the_model_before_a_bare_prompt_leaves_setup() -> None:
    """A bare prompt gets the same model check as a named target, while the
    setup log is still on screen to show the outcome."""
    verified = 0

    async def verify() -> None:
        nonlocal verified
        verified += 1

    async def start() -> None:
        return None

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start, on_verify=verify)

    await controller.handle("setup.start", {"mount_working_dir": True})

    assert verified == 1
    assert controller.setup_mode is False
    assert controller.pending_workspace_mount == str(Path.cwd())


@pytest.mark.asyncio
async def test_failed_model_check_keeps_the_start_screen() -> None:
    async def verify() -> None:
        raise RuntimeError("Model connection failed: timed out")

    async def start() -> None:
        pytest.fail("the scan must not start when the model check fails")

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start, on_verify=verify)

    with pytest.raises(RuntimeError, match="Model connection failed"):
        await controller.handle("setup.start", {"mount_working_dir": True})

    # Still on the start screen, so the error lands in the setup log and the
    # user can retry; no run was prepared behind a stuck live view.
    assert controller.setup_mode is True
    assert controller.scan_started is False
    assert controller.scan_state == "setup"
    assert controller.pending_workspace_mount is None


@pytest.mark.asyncio
async def test_confirmed_mount_launch_failure_is_reported_in_the_live_view() -> None:
    async def start() -> None:
        raise ValueError("Scan preparation failed")

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"mount_working_dir": True})

    with pytest.raises(ValueError, match="Scan preparation failed"):
        await controller.handle("setup.confirm_mount", {"approved": True})

    assert controller.scan_state == "failed"
    assert controller.error == "Scan preparation failed"


@pytest.mark.asyncio
async def test_start_rejects_concurrent_and_repeated_submissions() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def start() -> None:
        entered.set()
        await release.wait()

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    first_start = asyncio.create_task(controller.handle("setup.start", {}))
    await entered.wait()
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})
    release.set()
    await first_start
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "failed", "crashed", "stopped"])
async def test_stop_rejects_terminal_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> bool:
            self.calls.append(agent_id)
            return True

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    with pytest.raises(RuntimeError, match=f"cannot be stopped while {status}"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert coordinator.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "waiting", "budget_paused"])
async def test_stop_allows_active_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> bool:
            self.calls.append(agent_id)
            return True

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    result = await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert result == {"stopped": True}
    assert coordinator.calls == ["agent-1"]


@pytest.mark.asyncio
async def test_stop_handles_coordinator_rejection_after_stale_active_projection() -> None:
    class Coordinator:
        async def cancel_descendants_graceful(self, _agent_id: str) -> bool:
            return False

    controller = TuiController(args(), coordinator=Coordinator())
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status="running")

    with pytest.raises(RuntimeError, match="no longer active"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})


@pytest.mark.asyncio
async def test_unknown_command_is_rejected() -> None:
    controller = TuiController(args())
    with pytest.raises(ValueError, match="Unknown command"):
        await controller.handle("nope", {})


def test_messages_are_sanitized_and_agents_are_collection_only() -> None:
    controller = TuiController(args())
    controller.add_message("replace\x1b]52;c;Y2xpcA==\x07 key\x85")
    for index in range(40):
        controller.live_view.upsert_agent(f"agent-{index}", name=f"Agent {index}")

    snapshot = controller.snapshot()

    assert "agents" not in snapshot
    assert [message["text"] for message in snapshot["messages"]] == ["replace key"]
    assert len(controller.collection("agents")) == 40


def test_incidental_python_output_is_diagnostic_only(monkeypatch: pytest.MonkeyPatch) -> None:
    controller = TuiController(args())
    recorded: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        controller.notification_service,
        "record_output",
        lambda text, *, run_id=None: recorded.append((text, run_id)),
    )

    controller.record_output('  File "hooks.py", line 154, in on_llm_start')

    assert recorded == [('  File "hooks.py", line 154, in on_llm_start', None)]
    assert controller.messages == []


@pytest.mark.asyncio
async def test_existing_viewer_is_reopened_and_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    class ViewerServer:
        shutdown_called = False
        close_called = False

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.close_called = True

    controller = TuiController(args())
    controller.viewer_status = "running"
    controller.viewer_url = "http://127.0.0.1:1234/?token=test"
    server = ViewerServer()
    controller._viewer_httpd = server
    monkeypatch.setattr("strix.interface.tui.backend.controller.webbrowser.open", opened.append)

    result = await controller.handle("viewer.open", {})
    controller.close_viewer()

    assert result == {"status": "running", "url": controller.viewer_url}
    assert opened == [controller.viewer_url]
    assert server.shutdown_called is True
    assert server.close_called is True
