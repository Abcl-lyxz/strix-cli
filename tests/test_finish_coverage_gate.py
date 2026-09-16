"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.adapters.artifacts import JsonArtifactStore
from strix.tools.coverage.tools import _record_impl, get_coverage_entries
from strix.tools.finish.tool import _coverage_summary


if TYPE_CHECKING:
    from pathlib import Path


_GRAPH = {
    "statuses": {"agent-1": "completed"},
    "names": {"agent-1": "injection-tester"},
    "metadata": {"agent-1": {"skills": ["sql_injection", "xss"]}},
}


@pytest.fixture
def coverage_store(tmp_path: Path) -> JsonArtifactStore:
    return JsonArtifactStore(tmp_path / "coverage.json")


def _record(store: JsonArtifactStore, risk_area: str) -> None:
    _record_impl(
        store=store,
        surface="POST /api/orders/{id}",
        risk_area=risk_area,
        outcome="no_issue_found",
        evidence="Parameters fuzzed; no anomalies.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_unrecorded_risk_class_is_reported_back_to_the_root_agent(
    coverage_store: JsonArtifactStore,
) -> None:
    _record(coverage_store, "SQL injection")

    summary = _coverage_summary(_GRAPH, get_coverage_entries(coverage_store))

    assert summary["coverage_recorded"] == 1
    assert len(summary["coverage_gaps"]) == 1
    assert "xss" in summary["coverage_gaps"][0]
    assert "unexamined" in summary["coverage_gap_warning"]


def test_fully_accounted_coverage_raises_no_gap_warning(
    coverage_store: JsonArtifactStore,
) -> None:
    _record(coverage_store, "SQL injection")
    _record(coverage_store, "cross-site scripting")

    summary = _coverage_summary(_GRAPH, get_coverage_entries(coverage_store))

    assert "coverage_gaps" not in summary
    assert "coverage_gap_warning" not in summary


def test_an_empty_ledger_still_warns_first() -> None:
    summary = _coverage_summary(_GRAPH, [])

    assert summary["coverage_recorded"] == 0
    assert "No coverage was recorded" in summary["coverage_warning"]
