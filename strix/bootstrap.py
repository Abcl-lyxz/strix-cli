"""Composition root for process- and scan-scoped application services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from strix.application.context import AppServices, ScanContext
from strix.application.events import EventBus
from strix.notifications import NotificationService
from strix.ports.clock import SystemClock


if TYPE_CHECKING:
    from pathlib import Path

    from strix.ports.notifications import NotificationPublisher



def create_app_services() -> AppServices:
    return AppServices(
        events=EventBus(),
        clock=SystemClock(),
        notifications=cast("NotificationPublisher", NotificationService()),
    )


def create_scan_context(
    *,
    scan_id: str,
    run_dir: Path,
    state_dir: Path,
    report_state: Any,
    services: AppServices | None = None,
) -> ScanContext:
    app_services = services or create_app_services()
    if hasattr(report_state, "set_notification_publisher"):
        report_state.set_notification_publisher(app_services.notifications)
    return ScanContext(
        scan_id=scan_id,
        run_dir=run_dir,
        state_dir=state_dir,
        report_state=report_state,
        services=app_services,
    )
