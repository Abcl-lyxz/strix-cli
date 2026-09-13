"""SDK session helpers for Strix agents."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from weakref import WeakKeyDictionary

from agents.items import ItemHelpers
from agents.memory import SQLiteSession

from strix.security.secrets import redact_secrets, redact_value


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)


class _PooledConnectionSession(SQLiteSession):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._journal_suspended = 0
        self._initialize_journal()

    @contextmanager
    def _locked_connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeError("SQLiteSession is closed")
            if self._is_memory_db:
                yield self._shared_connection
                return
            connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            try:
                yield connection
            finally:
                connection.close()

    def _initialize_journal(self) -> None:
        with self._locked_connection() as connection:
            connection.executescript(
                """
                create table if not exists transcript_entries (
                    id integer primary key autoincrement,
                    session_id text not null,
                    message_data text not null,
                    source_message_id integer,
                    created_at timestamp default current_timestamp
                );
                create index if not exists idx_transcript_session
                    on transcript_entries(session_id, id);
                create unique index if not exists idx_transcript_source
                    on transcript_entries(source_message_id)
                    where source_message_id is not null;
                create table if not exists context_checkpoints (
                    id integer primary key autoincrement,
                    session_id text not null,
                    model text not null,
                    summary text not null,
                    state_json text not null,
                    compacted_items integer not null,
                    recent_items integer not null,
                    created_at timestamp default current_timestamp
                );
                """
            )
            # Backfill the history still available in pre-v1.7 databases once.
            connection.execute(
                """
                insert or ignore into transcript_entries(
                    session_id,message_data,source_message_id,created_at
                ) select session_id,message_data,id,created_at from agent_messages
                """
            )
            connection.commit()

    @contextmanager
    def suspend_journal(self) -> Iterator[None]:
        self._journal_suspended += 1
        try:
            yield
        finally:
            self._journal_suspended = max(0, self._journal_suspended - 1)

    async def add_items(self, items: list[TResponseInputItem]) -> None:
        if not items:
            return

        def _append() -> None:
            with self._locked_connection() as connection:
                self._insert_items(connection, items)
                if not self._journal_suspended:
                    connection.executemany(
                        "insert into transcript_entries(session_id,message_data) values (?,?)",
                        [(self.session_id, json.dumps(redact_value(item))) for item in items],
                    )
                connection.commit()

        await asyncio.to_thread(_append)

    async def replace_items_atomic(self, items: list[Any], expected: list[Any]) -> bool:
        """Commit a history projection in one transaction without touching the transcript."""

        def replace() -> bool:
            with self._locked_connection() as connection:
                try:
                    connection.execute("begin immediate")
                    rows = connection.execute(
                        "select message_data from agent_messages where session_id=? order by id",
                        (self.session_id,),
                    ).fetchall()
                    current = [json.loads(row[0]) for row in rows]
                    if current != expected:
                        connection.rollback()
                        return False
                    connection.execute(
                        "delete from agent_messages where session_id=?", (self.session_id,)
                    )
                    self._insert_items(connection, items)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                else:
                    return True

        return await asyncio.to_thread(replace)


def open_agent_session(agent_id: str, path: Path) -> SQLiteSession:
    path.parent.mkdir(parents=True, exist_ok=True)
    return _PooledConnectionSession(session_id=agent_id, db_path=path)


async def seed_initial_input(session: Session, initial_input: Any) -> bool:
    """Commit an agent's opening identity/task input before its first run cycle."""
    items = ItemHelpers.input_to_new_input_list(initial_input)
    if not items:
        return False
    async with session_write_lock(session):
        if await session.get_items():
            return False
        await session.add_items(items)
    return True


_IMAGE_REJECTED_TEXT = "[image rejected by the model]"
_IMAGE_ELIDED_TEXT = "[older screenshot elided to bound context memory]"
_INHERITED_IMAGE_TEXT = "[screenshot omitted from inherited context]"


def _output_has_image(item_dict: dict[str, Any]) -> bool:
    return (
        item_dict.get("type") == "function_call_output"
        and isinstance(item_dict.get("output"), list)
        and any(isinstance(b, dict) and b.get("type") == "input_image" for b in item_dict["output"])
    )


def _elided_output(item_dict: dict[str, Any], text: str) -> dict[str, Any]:
    # Replace only image blocks; sibling text blocks are preserved.
    output = item_dict.get("output")
    blocks = output if isinstance(output, list) else []
    return {
        "type": "function_call_output",
        "call_id": item_dict.get("call_id"),
        "output": [
            {"type": "input_text", "text": text}
            if isinstance(block, dict) and block.get("type") == "input_image"
            else block
            for block in blocks
        ],
    }


_session_write_locks: WeakKeyDictionary[Session, asyncio.Lock] = WeakKeyDictionary()


def session_write_lock(session: Session) -> asyncio.Lock:
    """Lock serialising all out-of-band writes to ``session``."""
    lock = _session_write_locks.get(session)
    if lock is None:
        lock = asyncio.Lock()
        _session_write_locks[session] = lock
    return lock


async def transform_session_items(
    session: Session,
    transform: Callable[[list[Any]], tuple[list[Any], bool]],
) -> bool:
    """Read-modify-write a session under its write lock, restoring on failure."""
    async with session_write_lock(session):
        items = await session.get_items()
        if not items:
            return False
        rebuilt, changed = transform(list(items))
        if not changed:
            return False
        if isinstance(session, _PooledConnectionSession):
            return await session.replace_items_atomic(rebuilt, list(items))
        rebuilt_items = cast("list[TResponseInputItem]", rebuilt)
        original_items = cast("list[TResponseInputItem]", list(items))
        with _journal_suspension(session):
            await session.clear_session()
            try:
                await session.add_items(rebuilt_items)
            except Exception:
                logger.exception("session rewrite failed; restoring original items")
                await session.clear_session()
                await session.add_items(original_items)
                raise
        return True


async def replace_session_items(
    session: Session,
    new_items: list[Any],
    *,
    expected_len: int | None = None,
) -> bool:
    """Overwrite the session's items, restoring the originals on failure.

    When ``expected_len`` is given, the rewrite is skipped if the session no
    longer has that many items (a concurrent writer changed it), so a slow
    compaction summary can't clobber newer turns.
    """
    async with session_write_lock(session):
        original = list(await session.get_items())
        if expected_len is not None and len(original) != expected_len:
            logger.warning(
                "skipping session rewrite: expected %d items, found %d",
                expected_len,
                len(original),
            )
            return False
        if isinstance(session, _PooledConnectionSession):
            return await session.replace_items_atomic(new_items, original)
        rebuilt = cast("list[TResponseInputItem]", new_items)
        with _journal_suspension(session):
            await session.clear_session()
            try:
                await session.add_items(rebuilt)
            except Exception:
                logger.exception("session rewrite failed; restoring original items")
                await session.clear_session()
                await session.add_items(original)
                raise
        return True


@contextmanager
def _journal_suspension(session: Session) -> Iterator[None]:
    suspend = getattr(session, "suspend_journal", None)
    if callable(suspend):
        with suspend():
            yield
        return
    yield


async def record_context_checkpoint(
    session: Session,
    *,
    model: str,
    summary: str,
    state: dict[str, Any],
    compacted_items: int,
    recent_items: int,
) -> None:
    """Append one structured compaction checkpoint when the session supports it."""
    if not isinstance(session, _PooledConnectionSession):
        return

    def _record() -> None:
        with session._locked_connection() as connection:
            connection.execute(
                """
                insert into context_checkpoints(
                    session_id,model,summary,state_json,compacted_items,recent_items
                ) values (?,?,?,?,?,?)
                """,
                (
                    session.session_id,
                    model,
                    redact_secrets(summary),
                    redact_secrets(json.dumps(state, ensure_ascii=False, default=str)),
                    compacted_items,
                    recent_items,
                ),
            )
            connection.commit()

    await asyncio.to_thread(_record)


def _read_checkpoint_json(path: Path) -> Any | None:
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _agent_checkpoint_fields(agents: dict[str, Any], session_id: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    metadata = agents.get("metadata")
    if isinstance(metadata, dict):
        agent_metadata = metadata.get(session_id)
        if isinstance(agent_metadata, dict) and agent_metadata.get("task"):
            fields["task"] = agent_metadata["task"]
    statuses = agents.get("statuses")
    if isinstance(statuses, dict):
        fields["pending_agents"] = {
            key: value for key, value in statuses.items() if value in {"running", "waiting"}
        }
    errors = agents.get("errors")
    if isinstance(errors, dict) and errors:
        fields["failed_attempts"] = errors
    return fields


def _finding_files(findings: Any) -> list[str]:
    relevant_files: set[str] = set()
    if not isinstance(findings, list):
        return []
    for finding in findings:
        locations = finding.get("code_locations") if isinstance(finding, dict) else None
        if not isinstance(locations, list):
            continue
        for location in locations:
            if not isinstance(location, dict):
                continue
            relevant_files.update(
                value
                for key in ("path", "file", "uri")
                if isinstance((value := location.get(key)), str) and value
            )
    return sorted(relevant_files)


def deterministic_context_state(session: Session) -> dict[str, Any]:
    """Read durable run ledgers used to anchor an LLM compaction summary."""
    path = getattr(session, "db_path", None)
    session_id = str(getattr(session, "session_id", ""))
    if not path or str(path) == ":memory:":
        return {"agent_id": session_id}
    state_dir = Path(str(path)).parent
    result: dict[str, Any] = {"agent_id": session_id}
    for name in ("agents", "todos", "notes", "coverage", "threat_models"):
        value = _read_checkpoint_json(state_dir / f"{name}.json")
        if value is None:
            continue
        result[name] = (
            value.get(session_id, {}) if name == "todos" and isinstance(value, dict) else value
        )

    agents = result.get("agents")
    if isinstance(agents, dict):
        result.update(_agent_checkpoint_fields(agents, session_id))
    for result_name, filename in (("run", "run.json"), ("findings", "vulnerabilities.json")):
        value = _read_checkpoint_json(state_dir.parent / filename)
        if value is not None:
            result[result_name] = value
    relevant_files = _finding_files(result.get("findings"))
    if relevant_files:
        result["relevant_files"] = relevant_files
    return result


async def strip_all_images_from_session(session: Session) -> bool:
    """Replace every image tool output with a text placeholder (rejection recovery)."""

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        rebuilt: list[Any] = []
        changed = False
        for item in items:
            item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
            if item_dict is not None and _output_has_image(item_dict):
                rebuilt.append(_elided_output(item_dict, _IMAGE_REJECTED_TEXT))
                changed = True
            else:
                rebuilt.append(item)
        return rebuilt, changed

    return await transform_session_items(session, _transform)


async def enforce_image_budget(session: Session, max_images: int) -> bool:
    """Keep only the most recent ``max_images`` image outputs; elide older ones."""
    if max_images < 0:
        return False

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        image_indices = [
            i
            for i, item in enumerate(items)
            if isinstance(item, dict) and _output_has_image(cast("dict[str, Any]", item))
        ]
        if len(image_indices) <= max_images:
            return items, False
        to_elide = set(image_indices[: len(image_indices) - max_images])
        rebuilt = [
            _elided_output(cast("dict[str, Any]", item), _IMAGE_ELIDED_TEXT)
            if i in to_elide
            else item
            for i, item in enumerate(items)
        ]
        return rebuilt, True

    return await transform_session_items(session, _transform)


def scrub_images_from_items(items: list[Any]) -> list[Any]:
    """Return a copy of ``items`` with every image block replaced by text."""

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            if obj.get("type") == "input_image":
                return {"type": "input_text", "text": _INHERITED_IMAGE_TEXT}
            return {k: _scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        return obj

    return [_scrub(item) for item in items]
