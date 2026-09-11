"""Durable transcript and deterministic compaction checkpoint tests."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.memory import SQLiteSession

from strix.core.sessions import (
    deterministic_context_state,
    open_agent_session,
    record_context_checkpoint,
    replace_session_items,
)


if TYPE_CHECKING:
    from pathlib import Path


def _transcript(path: Path, session_id: str) -> list[dict[str, Any]]:
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "select message_data from transcript_entries where session_id=? order by id",
            (session_id,),
        ).fetchall()
    return [cast("dict[str, Any]", json.loads(row[0])) for row in rows]


@pytest.mark.asyncio
async def test_working_memory_rewrites_never_erase_transcript(tmp_path: Path) -> None:
    path = tmp_path / ".state" / "agents.db"
    session = open_agent_session("root", path)
    original = [{"role": "user", "content": f"turn-{index}"} for index in range(8)]
    try:
        await session.add_items(original)
        await replace_session_items(
            session,
            [{"role": "user", "content": "checkpoint-one"}, *original[-2:]],
        )
        await replace_session_items(
            session,
            [{"role": "user", "content": "checkpoint-two"}, original[-1]],
        )
        await session.add_items([{"role": "assistant", "content": "continued"}])

        working = await session.get_items()
        transcript = _transcript(path, "root")
    finally:
        session.close()

    assert len(working) == 3
    assert [item["content"] for item in transcript] == [
        *(item["content"] for item in original),
        "continued",
    ]
    assert all("checkpoint" not in item["content"] for item in transcript)


@pytest.mark.asyncio
async def test_existing_messages_are_backfilled_exactly_once(tmp_path: Path) -> None:
    path = tmp_path / "agents.db"
    legacy = SQLiteSession("root", path)
    await legacy.add_items([{"role": "user", "content": "still available"}])
    legacy.close()

    first = open_agent_session("root", path)
    first.close()
    second = open_agent_session("root", path)
    second.close()

    transcript = _transcript(path, "root")
    assert [item["content"] for item in transcript] == ["still available"]


@pytest.mark.asyncio
async def test_checkpoint_records_summary_and_durable_state(tmp_path: Path) -> None:
    path = tmp_path / ".state" / "agents.db"
    session = open_agent_session("root", path)
    try:
        await record_context_checkpoint(
            session,
            model="fallback-model",
            summary="dense summary",
            state={"task": "review auth"},
            compacted_items=20,
            recent_items=4,
        )
    finally:
        session.close()

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "select model,summary,state_json,compacted_items,recent_items from context_checkpoints"
        ).fetchone()
    assert row == ("fallback-model", "dense summary", '{"task": "review auth"}', 20, 4)


def test_deterministic_state_includes_task_findings_failures_and_files(tmp_path: Path) -> None:
    state_dir = tmp_path / "run" / ".state"
    path = state_dir / "agents.db"
    session = open_agent_session("root", path)
    try:
        state_dir.joinpath("agents.json").write_text(
            json.dumps(
                {
                    "statuses": {"root": "running", "child": "waiting", "done": "completed"},
                    "metadata": {"root": {"task": "test the checkout flow"}},
                    "errors": {"old-child": "timed out probing /login"},
                }
            ),
            encoding="utf-8",
        )
        state_dir.joinpath("todos.json").write_text(
            json.dumps({"root": {"items": ["test reset"]}}), encoding="utf-8"
        )
        state_dir.joinpath("coverage.json").write_text(
            json.dumps({"tested": ["/login"]}), encoding="utf-8"
        )
        state_dir.parent.joinpath("run.json").write_text(
            json.dumps({"status": "running", "targets_info": ["example.test"]}),
            encoding="utf-8",
        )
        state_dir.parent.joinpath("vulnerabilities.json").write_text(
            json.dumps(
                [
                    {
                        "id": "vuln-0001",
                        "title": "Auth bypass",
                        "code_locations": [{"path": "src/auth.py", "line": 42}],
                    }
                ]
            ),
            encoding="utf-8",
        )

        state = deterministic_context_state(session)
    finally:
        session.close()

    assert state["task"] == "test the checkout flow"
    assert state["pending_agents"] == {"root": "running", "child": "waiting"}
    assert state["failed_attempts"] == {"old-child": "timed out probing /login"}
    assert state["todos"] == {"items": ["test reset"]}
    assert state["coverage"] == {"tested": ["/login"]}
    assert state["findings"][0]["id"] == "vuln-0001"
    assert state["relevant_files"] == ["src/auth.py"]
