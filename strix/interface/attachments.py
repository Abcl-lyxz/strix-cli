"""Explicit local attachments, including binary files and folder context."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from uuid import uuid4


MAX_ATTACHMENT_BYTES = 250 * 1024 * 1024
MAX_ATTACHMENT_FILES = 2000
_IGNORED = {".git", ".codex", ".agents", "node_modules", ".venv"}


def _folder_files(source: Path) -> Any:
    def unreadable(error: OSError) -> None:
        raise error

    for root, folders, filenames in os.walk(source, followlinks=False, onerror=unreadable):
        folders[:] = [
            name
            for name in folders
            if name not in _IGNORED and not (Path(root) / name).is_symlink()
        ]
        for filename in filenames:
            yield Path(root) / filename


def resolve_path(value: str) -> Path:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not value or any(ord(c) < 32 for c in value):
        raise ValueError("Enter a valid local path")
    return Path(os.path.expandvars(value)).expanduser().resolve(strict=True)


def describe_attachment(value: str, *, role: str = "context") -> dict[str, Any]:
    if role not in {"context", "target"}:
        raise ValueError("Attachment role must be context or target")
    source = resolve_path(value)
    identifier = uuid4().hex[:12]
    files: list[dict[str, str]] = []
    total = 0
    paths = _folder_files(source) if source.is_dir() else [source]
    for path in paths:
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(source) if source.is_dir() else Path(source.name)
        if source.is_dir() and any(
            part in {".git", ".codex", ".agents", "node_modules", ".venv"}
            for part in relative.parts
        ):
            continue
        total += path.stat().st_size
        if total > MAX_ATTACHMENT_BYTES or len(files) >= MAX_ATTACHMENT_FILES:
            raise ValueError("Attachment exceeds 250 MiB or 2,000 files; select a smaller folder")
        with path.open("rb"):
            pass
        files.append(
            {
                "source_path": str(path),
                "workspace_path": f"/workspace/attachments/{identifier}/{relative.as_posix()}",
            }
        )
    if not files:
        raise ValueError("Attachment contains no readable regular files")
    destination = (
        f"/workspace/attachments/{identifier}" if source.is_dir() else files[0]["workspace_path"]
    )
    return {
        "id": identifier,
        "name": source.name,
        "path": str(source),
        "role": role,
        "kind": "directory" if source.is_dir() else "file",
        "size": total,
        "workspace_path": destination,
        "files": files,
        "status": "ready",
    }


def complete_paths(query: str) -> list[dict[str, str]]:
    text = query.strip().lstrip("@").strip("\"'")
    path = Path(os.path.expandvars(text)).expanduser() if text else Path.cwd()
    root = path if path.is_dir() else path.parent
    prefix = "" if path.is_dir() else path.name.casefold()
    results: list[dict[str, str]] = []
    for child in sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name.casefold())):
        if child.name.casefold().startswith(prefix) and child.name not in {
            ".git",
            ".codex",
            ".agents",
        }:
            results.append(
                {
                    "path": str(child.resolve()),
                    "name": child.name,
                    "kind": "directory" if child.is_dir() else "file",
                }
            )
        if len(results) >= 100:
            break
    return results
