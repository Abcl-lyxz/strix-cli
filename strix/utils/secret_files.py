from __future__ import annotations

from typing import TYPE_CHECKING

from strix.utils.atomic import atomic_write_text


if TYPE_CHECKING:
    from pathlib import Path


SECRET_FILE_MODE = 0o600


def write_secret_text(path: Path, text: str) -> None:
    atomic_write_text(path, text, mode=SECRET_FILE_MODE)
