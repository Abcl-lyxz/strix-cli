"""Filesystem-backed repositories for run-scoped tool artifacts."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from strix.utils.atomic import atomic_write_text


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(slots=True)
class JsonArtifactStore:
    """One run-owned JSON document with synchronized in-memory access."""

    path: Path
    data: dict[str, Any] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)

    @classmethod
    def hydrate(cls, path: Path) -> JsonArtifactStore:
        store = cls(path=path)
        if not path.is_file():
            return store
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("%s is unreadable; starting with an empty artifact", path)
            return store
        if isinstance(payload, dict):
            store.data.update(payload)
        return store

    def persist(self) -> None:
        with self.lock:
            atomic_write_text(
                self.path,
                lambda: json.dumps(self.data, ensure_ascii=False, default=str),
            )

    def snapshot_entries(self, id_field: str) -> list[dict[str, Any]]:
        """Return detached mapping values with their stable keys attached."""

        with self.lock:
            return [
                {**value, id_field: key}
                for key, value in self.data.items()
                if isinstance(value, dict)
            ]
