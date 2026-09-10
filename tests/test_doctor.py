from __future__ import annotations

import json
from typing import Any

from strix.interface import doctor


def test_safe_endpoint_removes_proxy_credentials() -> None:
    assert doctor._safe_endpoint("http://alice:secret@127.0.0.1:8080/path") == (
        "http://127.0.0.1:8080"
    )


def test_loopback_proxy_gets_actionable_warning() -> None:
    result = doctor._proxy_check({"HTTPS_PROXY": "http://127.0.0.1:8080"})

    assert result["status"] == "warn"
    assert "Containers cannot reach" in result["fix"]


def test_doctor_json_exit_code_tracks_failed_checks(monkeypatch: Any, capsys: Any) -> None:
    report = {
        "ok": False,
        "platform": "test",
        "wsl": True,
        "checks": [{"name": "Docker daemon", "status": "fail", "detail": "offline"}],
    }
    monkeypatch.setattr(doctor, "collect_diagnostics", lambda **_kwargs: report)

    assert doctor.run_doctor(["--network", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == report
