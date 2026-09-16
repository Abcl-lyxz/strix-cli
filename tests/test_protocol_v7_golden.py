from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from strix.interface.tui.backend.protocol import PROTOCOL_VERSION, envelope


FIXTURE = Path(__file__).parent / "fixtures" / "protocol_v7_contract.json"


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_protocol_v7_golden_envelopes_match_python_encoder() -> None:
    fixture = _fixture()
    assert fixture["version"] == PROTOCOL_VERSION == 7
    for expected in fixture["envelopes"]:
        actual = envelope(
            expected["type"],
            expected["payload"],
            request_id=expected.get("request_id"),
        )
        assert actual == expected


def test_protocol_v7_fixture_keeps_checkpoint_identity() -> None:
    stream = _fixture()["workspace_stream"]
    assert stream["agents"][0]["id"] == stream["events"][0]["agent_id"]
    assert stream["events"][0]["data"]["content"] == "checkpoint"
