"""Ports for run-scoped structured artifacts."""

from __future__ import annotations

from typing import Any, Protocol


class ArtifactRepository(Protocol):
    data: dict[str, Any]
    lock: Any

    def persist(self) -> None: ...

    def snapshot_entries(self, id_field: str) -> list[dict[str, Any]]: ...
