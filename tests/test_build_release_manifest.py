from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from scripts.build_release_manifest import build_manifest


if TYPE_CHECKING:
    from pathlib import Path


def test_build_manifest_includes_nested_archives_and_wheels(tmp_path: Path) -> None:
    archive = tmp_path / "release" / "strix-1.7.0-windows-x86_64.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"standalone")
    wheel = tmp_path / "strix_agent-1.7.0-py3-none-win_amd64.whl"
    wheel.write_bytes(b"wheel")

    manifest = build_manifest(tmp_path, version="v1.7.0", commit="abc123")

    assert manifest["version"] == "1.7.0"
    assert manifest["release_commit"] == "abc123"
    assert manifest["supported_platforms"] == ["windows-x86_64"]
    assert manifest["assets"] == {
        archive.name: {
            "sha256": hashlib.sha256(b"standalone").hexdigest(),
            "size": 10,
            "kind": "binary",
        },
        wheel.name: {
            "sha256": hashlib.sha256(b"wheel").hexdigest(),
            "size": 5,
            "kind": "wheel",
        },
    }


def test_build_manifest_rejects_duplicate_asset_names(tmp_path: Path) -> None:
    first = tmp_path / "one" / "strix-1.7.0-linux-x86_64.tar.gz"
    second = tmp_path / "two" / first.name
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"one")
    second.write_bytes(b"two")

    with pytest.raises(ValueError, match="duplicate release asset name"):
        build_manifest(tmp_path, version="1.7.0", commit="abc123")
