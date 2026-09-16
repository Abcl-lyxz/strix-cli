"""Explicit process and per-scan dependency containers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from strix.application.events import EventBus
from strix.ports.clock import Clock, SystemClock


if TYPE_CHECKING:
    from pathlib import Path

    from strix.domain.execution import ExecutionState
    from strix.ports.artifacts import ArtifactRepository
    from strix.ports.notifications import NotificationPublisher


@dataclass(slots=True)
class AppServices:
    """Process-scoped immutable services assembled by the composition root."""

    notifications: NotificationPublisher
    events: EventBus = field(default_factory=EventBus)
    clock: Clock = field(default_factory=SystemClock)


@dataclass(slots=True)
class ScanContext:
    """Single owner of all mutable state belonging to one scan."""

    scan_id: str
    run_dir: Path
    state_dir: Path
    report_state: Any
    services: AppServices
    coordinator: Any = None
    route_pool: Any = None
    sandbox_session: Any = None
    caido_client: Any = None
    mcp_registry: Any = None
    execution_states: dict[str, ExecutionState] = field(default_factory=dict)
    artifact_stores: dict[str, ArtifactRepository] = field(default_factory=dict)
    runtime_resources: dict[str, Any] = field(default_factory=dict)

    def artifact_store(self, name: str) -> ArtifactRepository:
        """Return a repository owned by this scan, never process-global state."""

        try:
            return self.artifact_stores[name]
        except KeyError as exc:
            raise RuntimeError(f"Artifact repository {name!r} is not configured") from exc

    def runtime_resource(self, name: str, factory: Any) -> Any:
        """Resolve a lazily-created in-memory resource scoped to this scan."""

        if name not in self.runtime_resources:
            self.runtime_resources[name] = factory()
        return self.runtime_resources[name]

    def tool_context(self, **values: Any) -> dict[str, Any]:
        """Build the SDK context while retaining typed application ownership."""

        return {"scan_context": self, **values}
