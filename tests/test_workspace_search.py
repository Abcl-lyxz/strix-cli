"""Deterministic workspace-search engine tests."""

from __future__ import annotations

import json
import shutil
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.tools.workspace_search.engine import (
    build_rg_args,
    parse_rg_json,
    search_local_workspace,
)
from strix.tools.workspace_search.tool import workspace_search


if TYPE_CHECKING:
    from pathlib import Path


def test_rg_arguments_treat_a_dash_prefixed_query_as_data() -> None:
    args = build_rg_args(query="--help", root="/workspace", mode="fixed")

    separator = args.index("--")
    assert args[separator + 1 :] == ["--help", "/workspace"]
    assert "--fixed-strings" in args
    assert "--smart-case" in args


def test_parse_rg_json_returns_bounded_line_matches() -> None:
    records = [
        json.dumps(
            {
                "type": "match",
                "data": {
                    "path": {"text": f"/workspace/src/file:{line}.py"},
                    "lines": {"text": f"value = 'ade:{line}'\n"},
                    "line_number": line,
                    "submatches": [{"start": 9, "end": 12, "match": {"text": "ade"}}],
                },
            }
        )
        for line in range(1, 4)
    ]

    result = parse_rg_json(
        "\n".join(records),
        query="ade",
        root="/workspace",
        mode="fixed",
        max_results=2,
    )

    assert result["match_count"] == 3
    assert result["returned_count"] == 2
    assert result["truncated"] is True
    assert result["matches"][0] == {
        "path": "src/file:1.py",
        "line": 1,
        "column": 10,
        "text": "value = 'ade:1'",
    }


@pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep is not installed")
def test_local_workspace_search_finds_literal_text(tmp_path: Path) -> None:
    source = tmp_path / "example.py"
    source.write_text("needle = 'ade'\nnot_it = 'other'\n", encoding="utf-8")

    result = search_local_workspace(tmp_path, "ade")

    assert result["success"] is True
    assert result["match_count"] == 1
    assert result["matches"][0]["path"] == "example.py"
    assert result["matches"][0]["line"] == 1


@pytest.mark.asyncio
async def test_agent_tool_uses_safe_literal_search_inside_workspace() -> None:
    record = json.dumps(
        {
            "type": "match",
            "data": {
                "path": {"text": "/workspace/src/app.py"},
                "lines": {"text": "value = ade\n"},
                "line_number": 7,
                "submatches": [{"start": 8, "end": 11, "match": {"text": "ade"}}],
            },
        }
    )
    captured: dict[str, Any] = {}

    class Session:
        async def exec(self, *args: str, **kwargs: Any) -> Any:
            captured["args"] = args
            captured["kwargs"] = kwargs
            return SimpleNamespace(exit_code=0, stdout=record, stderr=b"")

    context = ToolContext(
        context={"sandbox_session": Session()},
        tool_name="workspace_search",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw = await workspace_search.on_invoke_tool(
        cast("Any", context),
        json.dumps({"query": "ade", "path": "src"}),
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["matches"][0]["path"] == "app.py"
    assert captured["args"][-3:] == ("--", "ade", "/workspace/src")
    assert captured["kwargs"] == {"timeout": 30}
