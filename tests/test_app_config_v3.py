from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.config import app_config
from strix.config.app_config import (
    AppConfig,
    AppConfigError,
    ConfigService,
    ConnectionProfile,
)


if TYPE_CHECKING:
    from pathlib import Path


class _Secrets:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def set(self, ref: str, value: str) -> None:
        self.values[ref] = value

    def get(self, ref: str) -> str | None:
        return self.values.get(ref)

    def delete(self, ref: str) -> bool:
        return self.values.pop(ref, None) is not None


def _profile() -> ConnectionProfile:
    return ConnectionProfile(
        id="primary",
        provider_id="openai",
        name="Primary",
        auth_source="keychain",
    )


def test_v3_does_not_read_or_overwrite_legacy_files(tmp_path: Path) -> None:
    legacy = tmp_path / "cli-config.json"
    legacy.write_text('{"llm":{"model":"openai/legacy"}}', encoding="utf-8")
    service = ConfigService(tmp_path / "config.json")

    assert service.load() == AppConfig()
    service.save(AppConfig())

    assert json.loads(legacy.read_text(encoding="utf-8"))["llm"]["model"] == ("openai/legacy")


def test_invalid_config_is_never_replaced_with_an_empty_document(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    service = ConfigService(path)
    service.save(AppConfig())
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(AppConfigError, match="last known good"):
        service.load()

    assert path.read_text(encoding="utf-8") == "{broken"
    assert service._last_good is not None  # verifies recovery invariant


def test_key_rotation_deletes_old_secret_only_after_config_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = _Secrets()
    monkeypatch.setattr(app_config, "get_secret_store", lambda: secrets)
    service = ConfigService(tmp_path / "config.json")
    first = service.upsert_connection(_profile(), secret="old-secret")  # noqa: S106
    second = service.upsert_connection(_profile(), secret="new-secret")  # noqa: S106

    assert first.secret_ref != second.secret_ref
    assert secrets.get(first.secret_ref or "") is None
    assert secrets.get(second.secret_ref or "") == "new-secret"


def test_failed_rotation_removes_new_secret_and_preserves_old_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = _Secrets()
    monkeypatch.setattr(app_config, "get_secret_store", lambda: secrets)
    service = ConfigService(tmp_path / "config.json")
    first = service.upsert_connection(_profile(), secret="old-secret")  # noqa: S106

    monkeypatch.setattr(
        service,
        "save",
        lambda _config: (_ for _ in ()).throw(OSError("disk full")),
    )
    with pytest.raises(OSError, match="disk full"):
        service.upsert_connection(_profile(), secret="new-secret")  # noqa: S106

    assert secrets.get(first.secret_ref or "") == "old-secret"
    assert all(value != "new-secret" for value in secrets.values.values())
