"""Persistence and delivery tests for the application-wide notification inbox."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix import notifications
from strix.notifications import NotificationAction, NotificationService
from strix.security import register_secret


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def service(tmp_path: Path) -> NotificationService:
    return NotificationService(tmp_path / "state.db")


def test_persists_filters_and_tracks_unread(service: NotificationService, tmp_path: Path) -> None:
    first = service.publish(
        "runtime.route.cooldown",
        title="Primary route cooling down",
        severity="warning",
        run_id="run-a",
        agent_id="root",
        route_id="primary",
    )
    service.publish(
        "finding.created",
        title="SQL injection",
        category="finding",
        severity="critical",
        run_id="run-b",
    )

    reopened = NotificationService(tmp_path / "state.db")
    assert reopened.unread_count() == 2
    assert [item.id for item in reopened.list(run_id="run-a")] == [first.id]
    assert [item.id for item in reopened.list(agent_id="root")] == [first.id]
    assert [item.id for item in reopened.list(route_id="primary")] == [first.id]
    assert len(reopened.list(severity="critical")) == 1
    assert reopened.mark_read(first.id) is True
    assert reopened.unread_count() == 1
    assert reopened.clear_read() == 1
    assert reopened.get(first.id) is not None
    assert reopened.get(first.id).dismissed is True  # type: ignore[union-attr]


def test_deduplicates_and_updates_latest_record(service: NotificationService) -> None:
    first = service.publish(
        "system.error",
        title="Provider unavailable",
        detail="first",
        severity="error",
        dedupe_key="provider:primary",
    )
    second = service.publish(
        "system.error",
        title="Provider still unavailable",
        detail="second",
        severity="critical",
        dedupe_key="provider:primary",
    )

    assert second.id == first.id
    assert second.count == 2
    assert second.detail == "second"
    assert second.updated_at >= first.updated_at
    assert len(service.list()) == 1


def test_event_namespace_is_open_and_actions_are_allowlisted(
    service: NotificationService,
) -> None:
    item = service.publish(
        "plugin.example.finished",
        title="Plugin finished",
        actions=(NotificationAction("dismiss", "Dismiss"),),
    )

    assert item.category == "plugin"
    assert item.actions[0].kind == "dismiss"
    with pytest.raises(ValueError, match="unsupported notification action"):
        NotificationAction("shell", "Run arbitrary command", "rm -rf")


def test_secrets_are_sanitized_before_persistence(service: NotificationService) -> None:
    register_secret("secret-value-123")

    item = service.publish(
        "security.credential_migration",
        title="Migrated secret-value-123",
        detail="api_key=secret-value-123",
        dedupe_key="secret-value-123",
    )

    assert "secret-value-123" not in json.dumps(item.to_dict())
    assert "secret-value-123" not in service.path.read_bytes().decode("utf-8", errors="ignore")


def test_preferences_control_immediate_surface(service: NotificationService) -> None:
    warning = service.publish(
        "runtime.route.cooldown",
        title="Cooling down",
        severity="warning",
    )
    info = service.publish("scan.completed", title="Done", severity="info")
    assert service.should_surface(warning) is True
    assert service.should_surface(info) is True

    service.set_preference("runtime", minimum_severity="error", immediate=True)
    assert service.should_surface(warning) is False
    service.set_preference("runtime", minimum_severity="info", immediate=False)
    assert service.should_surface(warning) is False


def test_category_floods_are_grouped_and_delivered(
    service: NotificationService, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(notifications, "_CATEGORY_NEW_LIMIT", 2)
    seen = []
    unsubscribe = service.subscribe(seen.append)
    try:
        service.publish("runtime.one", title="one")
        service.publish("runtime.two", title="two")
        grouped = service.publish("runtime.three", title="three")
        grouped_again = service.publish("runtime.four", title="four")
    finally:
        unsubscribe()

    assert grouped.event_type == "system.notifications.throttled"
    assert grouped_again.id == grouped.id
    assert grouped_again.count == 2
    assert seen[-1].id == grouped.id


def test_headless_json_is_emitted_only_on_stderr(
    service: NotificationService, capsys: pytest.CaptureFixture[str]
) -> None:
    service.configure_headless(enabled=True, structured=True)

    service.publish("agent.waiting", title="Agent parked", severity="warning")

    captured = capsys.readouterr()
    assert captured.out == ""
    payload = json.loads(captured.err)
    assert payload["type"] == "notification"
    assert payload["event_type"] == "agent.waiting"


def test_dismissed_dedupe_key_can_create_a_fresh_event(service: NotificationService) -> None:
    first = service.publish("update.failed", title="Failed", dedupe_key="update:1")
    assert service.dismiss(first.id) is True

    second = service.publish("update.failed", title="Failed again", dedupe_key="update:1")

    assert second.id != first.id
    assert len(service.list(include_dismissed=True)) == 2
