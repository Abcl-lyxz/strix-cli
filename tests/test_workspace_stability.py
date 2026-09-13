from __future__ import annotations

import asyncio
import ctypes
import json
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from strix.core.ownership import RunLease, run_is_active
from strix.core.sessions import open_agent_session, transform_session_items
from strix.interface.attachments import complete_paths, describe_attachment
from strix.interface.workspace import WorkspaceCommands
from strix.llm.errors import classify_model_failure
from strix.llm.tool_arguments import (
    InvalidToolArgumentsError,
    parse_tool_arguments,
    quarantine_history,
)
from strix.notifications import NotificationService
from strix.tools.browser.tool import BrowserSession
from strix.utils.atomic import atomic_write_text, storage_failures


@pytest.mark.parametrize(
    "value", ['{"x":NaN}', '{"x":Infinity}', '{"x":1e999}', "[]", "null", '{"x":']
)
def test_invalid_arguments_cannot_be_executed(value: str) -> None:
    with pytest.raises(InvalidToolArgumentsError):
        parse_tool_arguments(value)


@pytest.fixture
def recorded() -> dict:
    return json.loads((Path(__file__).parent / "fixtures" / "workspace_failures.json").read_text())


def test_recorded_errors_classify_as_malformed(recorded: dict) -> None:
    for message in recorded["provider_errors"]:
        assert classify_model_failure(RuntimeError(message)) == "malformed"


def test_quarantine_preserves_completed_actions_and_original_transcript(recorded: dict) -> None:
    original = json.dumps(recorded["history"])
    repaired, changed = quarantine_history(recorded["history"])
    assert changed
    assert repaired[-2:] == recorded["history"][-2:]
    assert "Recorded result" in repaired[1]["content"]
    assert json.dumps(recorded["history"]) == original
    assert quarantine_history(repaired) == (repaired, False)


@pytest.mark.asyncio
async def test_resumed_history_repair_is_atomic_and_keeps_journal(
    tmp_path: Path, recorded: dict
) -> None:
    path = tmp_path / "agents.db"
    session = open_agent_session("root", path)
    await session.add_items(recorded["history"])
    assert await transform_session_items(session, quarantine_history)
    repaired = await session.get_items()
    assert repaired[-2:] == recorded["history"][-2:]
    with sqlite3.connect(path) as connection:
        journal = [
            json.loads(row[0])
            for row in connection.execute("select message_data from transcript_entries order by id")
        ]
    assert journal == recorded["history"]
    session.close()
    resumed = open_agent_session("root", path)
    assert await resumed.get_items() == repaired
    resumed.close()


def test_windows_sharing_retry_preserves_last_valid_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "run.json"
    atomic_write_text(destination, '{"revision":1}')
    replace = Path.replace
    attempts = 0

    def locked(path: Path, target: Path) -> Path:
        nonlocal attempts
        attempts += 1
        assert json.loads(destination.read_text())["revision"] == 1
        if attempts < 3:
            raise PermissionError("sharing violation")
        return replace(path, target)

    monkeypatch.setattr(Path, "replace", locked)
    atomic_write_text(destination, '{"revision":2}')
    assert attempts == 3
    assert json.loads(destination.read_text())["revision"] == 2
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.skipif(sys.platform != "win32", reason="Exercises a real Windows file-sharing lock")
def test_real_windows_file_lock_preserves_snapshot_until_release(tmp_path: Path) -> None:
    path = tmp_path / "locked-run.json"
    atomic_write_text(path, '{"revision":1}')
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    close = kernel.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    # Readers and writers are allowed, but replacing/deleting the open file is not.
    handle = create(str(path), 0x80000000, 3, None, 3, 128, None)
    assert handle != ctypes.c_void_p(-1).value
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            saved = pool.submit(atomic_write_text, path, '{"revision":2}')
            time.sleep(0.1)
            assert not saved.done()
            assert json.loads(path.read_text())["revision"] == 1
        finally:
            close(handle)
        saved.result(timeout=5)
    assert json.loads(path.read_text())["revision"] == 2
    assert not list(tmp_path.glob("*.tmp"))


def test_failed_save_is_visible_and_cleans_temp_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "run.json"
    atomic_write_text(path, "old")
    replace = Path.replace
    monkeypatch.setattr(Path, "replace", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        atomic_write_text(path, "new")
    assert path.read_text() == "old"
    assert storage_failures(tmp_path)
    assert not list(tmp_path.glob("*.tmp"))
    monkeypatch.setattr(Path, "replace", replace)
    atomic_write_text(path, "new")
    assert not storage_failures(tmp_path)


def test_run_lease_excludes_duplicate_owners(tmp_path: Path) -> None:
    lease = RunLease(tmp_path)
    lease.acquire()
    try:
        assert run_is_active(tmp_path)
        with pytest.raises(RuntimeError):
            RunLease(tmp_path).acquire()
    finally:
        lease.close()
    assert not run_is_active(tmp_path)


def test_binary_and_unicode_attachment_paths(tmp_path: Path) -> None:
    path = tmp_path / "日本語 target file.bin"
    path.write_bytes(bytes(range(256)))
    attachment = describe_attachment(f'"{path}"', role="target")
    assert attachment["size"] == 256
    assert attachment["workspace_path"].endswith(path.name)
    assert "content" not in attachment
    assert any(item["name"] == path.name for item in complete_paths(str(tmp_path)))


@pytest.mark.asyncio
async def test_shared_command_deduplication_across_clients() -> None:
    controller = SimpleNamespace(handle=AsyncMock(return_value={"accepted": True}))
    workspace = WorkspaceCommands(controller)
    results = await asyncio.gather(
        *(workspace.dispatch("scan.submit", {"message": "hello"}, "same") for _ in range(10))
    )
    assert all(result == {"accepted": True} for result in results)
    assert controller.handle.await_count == 1
    with pytest.raises(ValueError, match="reused"):
        await workspace.dispatch("scan.submit", {"message": "different"}, "same")


def test_notification_incident_coalesces_and_retains_audit(tmp_path: Path) -> None:
    service = NotificationService(tmp_path / "state.db")
    event = service.publish(
        "runtime.route.cooldown", title="Provider cooling down", dedupe_key="run:provider"
    )
    service.mark_read(event.id)
    for _ in range(20):
        repeated = service.publish(
            "runtime.route.cooldown", title="Provider cooling down", dedupe_key="run:provider"
        )
    assert repeated.id == event.id
    assert service.unread_count() == 0
    assert repeated.count == 21
    with sqlite3.connect(service.path) as connection:
        assert connection.execute("select count(*) from notification_events").fetchone()[0] == 21


@pytest.mark.asyncio
async def test_browser_isolation_and_no_write_replay() -> None:
    sandbox = SimpleNamespace(
        exec=AsyncMock(
            return_value=SimpleNamespace(
                stdout=b'{"success":false,"error":"stale ref"}', stderr=b"", ok=lambda: False
            )
        )
    )
    first = BrowserSession(
        {"scan_id": "synthetic", "agent_id": "first", "sandbox_session": sandbox}
    )
    second = BrowserSession(
        {"scan_id": "synthetic", "agent_id": "second", "sandbox_session": sandbox}
    )
    assert first.name != second.name
    result = await first.action("click", "@e1", "")
    assert not result["success"]
    assert sandbox.exec.await_count == 1
    assert sandbox.exec.call_args.args[1:3] == ("--session", first.name)
    await first.action("snapshot", "", "")
    assert sandbox.exec.await_count == 3


@pytest.mark.parametrize(
    "action,selector,value",
    [
        ("upload", "@e1", "/etc/passwd"),
        ("upload", "@e1", "/workspace/../etc/passwd"),
        ("click", "--session", "other"),
        ("open", "", "file:///etc/passwd"),
    ],
)
def test_browser_parameter_boundaries(action: str, selector: str, value: str) -> None:
    with pytest.raises(ValueError):
        BrowserSession.arguments(action, selector, value)
