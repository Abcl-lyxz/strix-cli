"""coverage.json is a deliverable artifact, not runtime state."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.adapters.artifacts import JsonArtifactStore
from strix.core.paths import runtime_state_dir
from strix.report.state import ReportState
from strix.tools.coverage.tools import _record_impl


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ReportState, JsonArtifactStore]:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="run-1")
    store = JsonArtifactStore(runtime_state_dir(report_state.get_run_dir()) / "coverage.json")
    report_state.set_coverage_entries_provider(lambda: store.snapshot_entries("entry_id"))
    return report_state, store


def _record_a_cleared_surface(store: JsonArtifactStore) -> None:
    _record_impl(
        store=store,
        surface="POST /api/orders/{id}",
        risk_area="SQL injection",
        outcome="no_issue_found",
        evidence="14 parameters fuzzed; every query parameterized.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_coverage_is_written_beside_the_other_artifacts(
    state: tuple[ReportState, JsonArtifactStore],
) -> None:
    report_state, store = state
    _record_a_cleared_surface(store)

    report_state._save_artifacts()

    document = json.loads(
        (report_state.get_run_dir() / "coverage.json").read_text(encoding="utf-8")
    )
    assert document["entries"][0]["risk_area"] == "SQL injection"
    assert document["summary"]["surfaces_reviewed"] == 1


def test_cleared_surfaces_reach_sarif(
    state: tuple[ReportState, JsonArtifactStore],
) -> None:
    report_state, store = state
    _record_a_cleared_surface(store)

    report_state._save_artifacts()

    sarif = json.loads((report_state.get_run_dir() / "findings.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert [result["kind"] for result in results] == ["pass"]


def test_artifacts_still_land_when_coverage_is_empty(
    state: tuple[ReportState, JsonArtifactStore],
) -> None:
    report_state, _store = state
    report_state.final_scan_result = "Scan complete."

    report_state._save_artifacts()

    run_dir = report_state.get_run_dir()
    assert (run_dir / "penetration_test_report.md").is_file()
    document = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
    assert document["entries"] == []
