"""Build the deterministic integrity manifest uploaded with a Strix release."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(directory: Path, *, version: str, commit: str) -> dict[str, Any]:
    assets: dict[str, dict[str, str | int]] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name == "release-manifest.json":
            continue
        name = path.name
        if name in assets:
            raise ValueError(f"duplicate release asset name: {name}")
        kind = "wheel" if name.endswith(".whl") else "binary"
        assets[name] = {
            "sha256": sha256(path),
            "size": path.stat().st_size,
            "kind": kind,
        }
    return {
        "schema_version": 1,
        "version": version.lstrip("v"),
        "release_commit": commit,
        "supported_platforms": [
            platform
            for platform in (
                "linux-x86_64",
                "linux-arm64",
                "macos-x86_64",
                "macos-arm64",
                "windows-x86_64",
            )
            if any(platform in name for name in assets)
        ],
        "provenance": {
            "repository": "https://github.com/Abcl-lyxz/strix-cli",
            "workflow": ".github/workflows/build-release.yml",
        },
        "assets": assets,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.directory, version=args.version, commit=args.commit)
    output = args.directory / "release-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
