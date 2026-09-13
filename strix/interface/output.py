"""Capture incidental Python output as redacted, structured UI messages."""

from __future__ import annotations

import io
import threading
from typing import TYPE_CHECKING

from strix.security.secrets import redact_secrets


if TYPE_CHECKING:
    from collections.abc import Callable


class WorkspaceOutput(io.TextIOBase):
    def __init__(self, emit: Callable[[str], object]) -> None:
        self.emit = emit
        self.pending = ""
        self.lock = threading.RLock()

    encoding = "utf-8"

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        with self.lock:
            self.pending += value.replace("\r\n", "\n").replace("\r", "\n")
            while "\n" in self.pending or len(self.pending) > 4000:
                index = self.pending.find("\n")
                index = index if 0 <= index < 4000 else 4000
                line = self.pending[:index]
                skip = 1 if self.pending[index : index + 1] == "\n" else 0
                self.pending = self.pending[index + skip :]
                if line.strip():
                    self.emit(redact_secrets(line))
        return len(value)

    def flush(self) -> None:
        with self.lock:
            if self.pending.strip():
                self.emit(redact_secrets(self.pending))
            self.pending = ""
