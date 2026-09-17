from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from strix.interface.tui.backend.protocol import PROTOCOL_VERSION, envelope


FIXTURE = Path(__file__).parent / "fixtures" / "protocol_v8_contract.json"


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_protocol_v8_golden_envelopes_match_python_encoder() -> None:
    fixture = _fixture()
    assert fixture["version"] == PROTOCOL_VERSION == 8
    for expected in fixture["envelopes"]:
        actual = envelope(
            expected["type"],
            expected["payload"],
            request_id=expected.get("request_id"),
        )
        assert actual == expected


def test_protocol_v8_fixture_has_no_manual_retry_command() -> None:
    commands = [
        envelope["payload"].get("command")
        for envelope in _fixture()["envelopes"]
        if envelope["type"] in {"command", "command_result"}
    ]
    assert commands == ["router.status", "router.status"]
