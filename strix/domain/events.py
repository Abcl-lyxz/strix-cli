"""Domain events shared by application services and presentation projectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """One immutable fact emitted by a Strix use case."""

    name: str
    data: dict[str, Any] = field(default_factory=dict)
    occurred_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    run_id: str | None = None
    agent_id: str | None = None
