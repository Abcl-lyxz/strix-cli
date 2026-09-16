"""Application-wide, durable Strix notifications.

Publishers use open-ended namespaced event types. The store keeps sanitized
metadata only and deliberately limits actions to UI-known operations.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

from strix.security.secrets import redact_secrets


Severity = Literal["info", "warning", "error", "critical"]
_SEVERITY_ORDER: dict[str, int] = {"info": 0, "warning": 1, "error": 2, "critical": 3}
_ALLOWED_ACTIONS = frozenset(
    {
        "dismiss",
        "open_agent",
        "open_finding",
        "open_routes",
        "retry_route_test",
        "start_update",
    }
)
_DEFAULT_PATH = Path.home() / ".strix" / "state.db"
_MAX_DETAIL_CHARS = 4_000
_MAX_TITLE_CHARS = 160
_CATEGORY_WINDOW_SECONDS = 60
_CATEGORY_NEW_LIMIT = 20

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class NotificationAction:
    kind: str
    label: str
    target: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in _ALLOWED_ACTIONS:
            raise ValueError(f"unsupported notification action: {self.kind}")
        if not self.label.strip() or len(self.label) > 80:
            raise ValueError("notification action label must be 1-80 characters")


@dataclass(frozen=True, slots=True)
class Notification:
    id: str
    event_type: str
    category: str
    severity: Severity
    title: str
    detail: str
    created_at: str
    updated_at: str
    unread: bool = True
    dismissed: bool = False
    count: int = 1
    dedupe_key: str | None = None
    run_id: str | None = None
    agent_id: str | None = None
    route_id: str | None = None
    actions: tuple[NotificationAction, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["actions"] = [asdict(action) for action in self.actions]
        result["resolved"] = self.event_type.endswith(".recovered")
        return result


class NotificationService:
    """SQLite-backed inbox shared by CLI, TUI, updater, and runtime producers."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _DEFAULT_PATH
        self._lock = threading.RLock()
        self._subscribers: list[Any] = []
        self._headless = False
        self._structured_headless = False
        self._last_surfaced: dict[str, tuple[str, str]] = {}
        self._initialize()

    def configure_headless(self, *, enabled: bool, structured: bool = False) -> None:
        """Emit newly published events to stderr for non-interactive runs."""
        self._headless = enabled
        self._structured_headless = structured

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("pragma busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("pragma journal_mode=WAL")
            connection.executescript(
                """
                create table if not exists notifications (
                    id text primary key,
                    event_type text not null,
                    category text not null,
                    severity text not null,
                    title text not null,
                    detail text not null,
                    created_at text not null,
                    updated_at text not null,
                    unread integer not null default 1,
                    dismissed integer not null default 0,
                    count integer not null default 1,
                    dedupe_key text,
                    run_id text,
                    agent_id text,
                    route_id text,
                    actions_json text not null default '[]'
                );
                create unique index if not exists notifications_dedupe
                    on notifications(dedupe_key) where dedupe_key is not null and dismissed = 0;
                create index if not exists notifications_updated
                    on notifications(updated_at desc);
                create table if not exists notification_events (
                    id integer primary key autoincrement,
                    event_type text not null, title text not null, detail text not null,
                    severity text not null, created_at text not null, run_id text, route_id text
                );
                create table if not exists notification_preferences (
                    category text primary key,
                    minimum_severity text not null,
                    immediate integer not null
                );
                """
            )

    def subscribe(self, callback: Any) -> Any:
        """Register an in-process sink; returns an unsubscribe callback."""
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def record_output(self, detail: str, *, run_id: str | None = None) -> None:
        """Retain incidental output without creating one inbox item per line."""
        with self._lock, self._connect() as connection:
            connection.execute(
                "insert into notification_events "
                "(event_type,title,detail,severity,created_at,run_id) values (?,?,?,?,?,?)",
                (
                    "ui.output",
                    "Application output",
                    redact_secrets(detail),
                    "info",
                    datetime.now(UTC).isoformat(),
                    run_id,
                ),
            )

    def publish(  # noqa: PLR0912 - validates and commits one durable event
        self,
        event_type: str,
        *,
        title: str,
        detail: str = "",
        severity: Severity = "info",
        category: str | None = None,
        dedupe_key: str | None = None,
        run_id: str | None = None,
        agent_id: str | None = None,
        route_id: str | None = None,
        actions: tuple[NotificationAction, ...] | list[NotificationAction] = (),
    ) -> Notification:
        if "." not in event_type or any(char.isspace() for char in event_type):
            raise ValueError("notification event type must be a namespaced value")
        if severity not in _SEVERITY_ORDER:
            raise ValueError(f"unsupported notification severity: {severity}")
        resolved_category = (category or event_type.split(".", 1)[0]).strip().lower()
        if not resolved_category:
            raise ValueError("notification category cannot be empty")
        safe_title = redact_secrets(title).strip()[:_MAX_TITLE_CHARS]
        safe_detail = redact_secrets(detail).strip()[:_MAX_DETAIL_CHARS]
        if not safe_title:
            raise ValueError("notification title cannot be empty")
        safe_actions = tuple(actions)
        now = datetime.now(UTC).isoformat()
        normalized_dedupe = redact_secrets(dedupe_key) if dedupe_key else None
        notification: Notification | None = None

        with self._lock, self._connect() as connection:
            connection.execute(
                "insert into notification_events(event_type,title,detail,severity,created_at,"
                "run_id,route_id) values (?,?,?,?,?,?,?)",
                (event_type, safe_title, safe_detail, severity, now, run_id, route_id),
            )
            existing = None
            if normalized_dedupe:
                existing = connection.execute(
                    "select id,severity,event_type from notifications "
                    "where dedupe_key = ? and dismissed = 0",
                    (normalized_dedupe,),
                ).fetchone()
            if existing is not None:
                notification_id = str(existing["id"])
                connection.execute(
                    """
                    update notifications
                    set event_type=?, category=?, severity=?, title=?, detail=?, updated_at=?,
                        unread=case when severity<>? or event_type<>? then 1 else unread end,
                        count=count+1, run_id=?, agent_id=?, route_id=?, actions_json=?
                    where id=?
                    """,
                    (
                        event_type,
                        resolved_category,
                        severity,
                        safe_title,
                        safe_detail,
                        now,
                        severity,
                        event_type,
                        run_id,
                        agent_id,
                        route_id,
                        _encode_actions(safe_actions),
                        notification_id,
                    ),
                )
            else:
                notification_id = uuid.uuid4().hex
                if severity not in {"error", "critical"} and self._category_is_flooding(
                    connection, resolved_category, now
                ):
                    notification = self._publish_throttled(connection, resolved_category, now)
                else:
                    connection.execute(
                        """
                        insert into notifications (
                            id,event_type,category,severity,title,detail,created_at,updated_at,
                            unread,dismissed,count,dedupe_key,run_id,agent_id,route_id,actions_json
                        ) values (?,?,?,?,?,?,?,?,1,0,1,?,?,?,?,?)
                        """,
                        (
                            notification_id,
                            event_type,
                            resolved_category,
                            severity,
                            safe_title,
                            safe_detail,
                            now,
                            now,
                            normalized_dedupe,
                            run_id,
                            agent_id,
                            route_id,
                            _encode_actions(safe_actions),
                        ),
                    )
                    row = connection.execute(
                        "select * from notifications where id = ?", (notification_id,)
                    ).fetchone()
                    notification = _row_to_notification(row)
            if existing is not None:
                row = connection.execute(
                    "select * from notifications where id = ?", (notification_id,)
                ).fetchone()
                notification = _row_to_notification(row)
        if notification is None:
            raise RuntimeError("notification could not be persisted")
        for subscriber in tuple(self._subscribers):
            try:
                subscriber(notification)
            except Exception:
                logger.exception("notification subscriber failed")
        if self._headless:
            if self._structured_headless:
                sys.stderr.write(
                    json.dumps({"type": "notification", **notification.to_dict()}) + "\n"
                )
            else:
                sys.stderr.write(
                    f"strix: [{notification.severity}] {notification.title}"
                    + (f": {notification.detail}" if notification.detail else "")
                    + "\n"
                )
        return notification

    def _category_is_flooding(
        self, connection: sqlite3.Connection, category: str, now: str
    ) -> bool:
        threshold = (
            datetime.fromisoformat(now) - timedelta(seconds=_CATEGORY_WINDOW_SECONDS)
        ).isoformat()
        row = connection.execute(
            "select count(*) as total from notifications where category=? and created_at>=?",
            (category, threshold),
        ).fetchone()
        return bool(row and int(row["total"]) >= _CATEGORY_NEW_LIMIT)

    def _publish_throttled(
        self, connection: sqlite3.Connection, category: str, now: str
    ) -> Notification:
        key = f"notification-flood:{category}"
        row = connection.execute(
            "select * from notifications where dedupe_key=? and dismissed=0", (key,)
        ).fetchone()
        if row is not None:
            connection.execute(
                "update notifications set count=count+1, updated_at=?, unread=1 where id=?",
                (now, row["id"]),
            )
            row = connection.execute(
                "select * from notifications where id=?", (row["id"],)
            ).fetchone()
            return _row_to_notification(row)
        notification_id = uuid.uuid4().hex
        connection.execute(
            """
            insert into notifications (
                id,event_type,category,severity,title,detail,created_at,updated_at,
                unread,dismissed,count,dedupe_key,actions_json
            ) values (?,?,?,?,?,?,?,?,1,0,1,?, '[]')
            """,
            (
                notification_id,
                "system.notifications.throttled",
                category,
                "warning",
                f"{category.title()} notifications were grouped",
                "Repeated events are still being counted without flooding the interface.",
                now,
                now,
                key,
            ),
        )
        row = connection.execute(
            "select * from notifications where id=?", (notification_id,)
        ).fetchone()
        return _row_to_notification(row)

    def list(
        self,
        *,
        unread: bool | None = None,
        severity: Severity | None = None,
        category: str | None = None,
        run_id: str | None = None,
        agent_id: str | None = None,
        route_id: str | None = None,
        include_dismissed: bool = False,
        limit: int = 100,
    ) -> list[Notification]:
        clauses = [] if include_dismissed else ["dismissed=0"]
        values: list[Any] = []
        for column, value in (
            ("unread", None if unread is None else int(unread)),
            ("severity", severity),
            ("category", category),
            ("run_id", run_id),
            ("agent_id", agent_id),
            ("route_id", route_id),
        ):
            if value is not None:
                clauses.append(f"{column}=?")
                values.append(value)
        where = f" where {' and '.join(clauses)}" if clauses else ""
        values.append(max(1, min(limit, 1_000)))
        with self._connect() as connection:
            # ``where`` contains only the fixed column names assembled above.
            query = f"select * from notifications{where} order by updated_at desc limit ?"  # nosec B608  # noqa: S608
            rows = connection.execute(query, values).fetchall()
        return [_row_to_notification(row) for row in rows]

    def get(self, notification_id: str) -> Notification | None:
        with self._connect() as connection:
            row = connection.execute(
                "select * from notifications where id=?", (notification_id,)
            ).fetchone()
        return _row_to_notification(row) if row is not None else None

    def mark_read(self, notification_id: str) -> bool:
        return self._set_flag(notification_id, "unread", value=False)

    def dismiss(self, notification_id: str) -> bool:
        return self._set_flag(notification_id, "dismissed", value=True)

    def clear_read(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute("update notifications set dismissed=1 where unread=0")
            return cursor.rowcount

    def unread_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "select count(*) as total from notifications where unread=1 and dismissed=0"
            ).fetchone()
        return int(row["total"]) if row is not None else 0

    def _set_flag(self, notification_id: str, column: str, value: bool) -> bool:
        if column not in {"unread", "dismissed"}:
            raise ValueError("unsupported notification flag")
        with self._connect() as connection:
            query = f"update notifications set {column}=? where id=?"  # nosec B608  # noqa: S608
            cursor = connection.execute(query, (int(value), notification_id))
            return cursor.rowcount > 0

    def set_preference(self, category: str, *, minimum_severity: Severity, immediate: bool) -> None:
        if minimum_severity not in _SEVERITY_ORDER:
            raise ValueError("unsupported minimum severity")
        with self._connect() as connection:
            connection.execute(
                """
                insert into notification_preferences(category,minimum_severity,immediate)
                values(?,?,?) on conflict(category) do update set
                    minimum_severity=excluded.minimum_severity, immediate=excluded.immediate
                """,
                (category.strip().lower(), minimum_severity, int(immediate)),
            )

    def should_surface(self, notification: Notification) -> bool:
        # A repeated event updates its incident without stealing focus again.
        signature = (notification.event_type, notification.severity)
        if self._last_surfaced.get(notification.id) == signature:
            return False
        self._last_surfaced[notification.id] = signature
        with self._connect() as connection:
            row = connection.execute(
                "select minimum_severity, immediate from notification_preferences where category=?",
                (notification.category,),
            ).fetchone()
        if row is not None:
            configured = _SEVERITY_ORDER[str(row["minimum_severity"])]
            return bool(row["immediate"]) and _SEVERITY_ORDER[notification.severity] >= configured
        if notification.event_type in {
            "update.available",
            "scan.completed",
            "runtime.route.recovered",
        }:
            return True
        return _SEVERITY_ORDER[notification.severity] >= _SEVERITY_ORDER["warning"]


def _encode_actions(actions: tuple[NotificationAction, ...]) -> str:
    return json.dumps([asdict(action) for action in actions], separators=(",", ":"))


def _row_to_notification(row: sqlite3.Row) -> Notification:
    try:
        raw_actions = cast("object", json.loads(str(row["actions_json"])))
    except (TypeError, json.JSONDecodeError):
        raw_actions = []
    actions: list[NotificationAction] = []
    raw_items = cast("list[object]", raw_actions) if isinstance(raw_actions, list) else []
    for raw_value in raw_items:
        raw = cast("dict[str, object]", raw_value) if isinstance(raw_value, dict) else None
        if raw is None:
            continue
        try:
            actions.append(
                NotificationAction(
                    kind=str(raw.get("kind", "")),
                    label=str(raw.get("label", "")),
                    target=str(raw["target"]) if raw.get("target") is not None else None,
                )
            )
        except ValueError:
            continue
    return Notification(
        id=str(row["id"]),
        event_type=str(row["event_type"]),
        category=str(row["category"]),
        severity=str(row["severity"]),  # type: ignore[arg-type]
        title=str(row["title"]),
        detail=str(row["detail"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        unread=bool(row["unread"]),
        dismissed=bool(row["dismissed"]),
        count=int(row["count"]),
        dedupe_key=row["dedupe_key"],
        run_id=row["run_id"],
        agent_id=row["agent_id"],
        route_id=row["route_id"],
        actions=tuple(actions),
    )


def notify(event_type: str, **kwargs: Any) -> Notification | None:
    """Persist one pre-composition incident without a process-global service."""
    try:
        return NotificationService().publish(event_type, **kwargs)
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return None
