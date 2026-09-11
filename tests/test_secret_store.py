"""Credential backend and transactional migration tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.config import loader
from strix.security import (
    SecretStore,
    SecretStoreUnavailableError,
    redact_secrets,
    register_secret,
)
from strix.security import secrets as secret_module


if TYPE_CHECKING:
    from pathlib import Path


class MemoryBackend:
    name = "memory"

    def __init__(self, *, available: bool = True, mismatch: bool = False) -> None:
        self.available = available
        self.mismatch = mismatch
        self.values: dict[str, str] = {}
        self.deleted: list[str] = []

    def get(self, ref: str) -> str | None:
        value = self.values.get(ref)
        return f"{value}-wrong" if self.mismatch and value is not None else value

    def set(self, ref: str, value: str) -> None:
        self.values[ref] = value

    def delete(self, ref: str) -> bool:
        self.deleted.append(ref)
        return self.values.pop(ref, None) is not None


class ChunkedMemoryBackend(MemoryBackend):
    max_value_bytes = 400

    @staticmethod
    def encoded_size(value: str) -> int:
        return len(value.encode("utf-8"))


def test_write_is_verified_before_success() -> None:
    backend = MemoryBackend()
    store = SecretStore(backend)

    store.set("route.Primary.API-Key", "sk-test-value")

    assert store.get("route.primary.api-key") == "sk-test-value"


def test_unavailable_backend_refuses_persistent_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notified: list[str] = []
    monkeypatch.setattr(
        secret_module,
        "_notify_credential_required",
        notified.append,
    )
    store = SecretStore(MemoryBackend(available=False))

    with pytest.raises(SecretStoreUnavailableError, match="environment variable"):
        store.set("route.primary.api-key", "sk-test-value")
    assert store.get("route.primary.api-key") is None
    assert notified == ["memory"]


def test_failed_verification_rolls_back_keychain_entry() -> None:
    backend = MemoryBackend(mismatch=True)
    store = SecretStore(backend)

    with pytest.raises(SecretStoreUnavailableError, match="verification failed"):
        store.set("route.primary.api-key", "sk-test-value")

    assert backend.values == {}
    assert backend.deleted == ["route.primary.api-key"]


def test_large_credentials_are_transparently_chunked() -> None:
    backend = ChunkedMemoryBackend()
    store = SecretStore(backend)
    value = json.dumps({"access_token": "x" * 450, "refresh_token": "y" * 450})

    store.set("oauth.chatgpt", value)

    assert store.get("oauth.chatgpt") == value
    assert backend.values["oauth.chatgpt"].startswith("strix-secret-chunks-v1:")
    assert len([ref for ref in backend.values if ".chunk." in ref]) > 1


def test_replacing_chunked_credential_removes_old_chunks() -> None:
    backend = ChunkedMemoryBackend()
    store = SecretStore(backend)
    store.set("oauth.chatgpt", "x" * 900)
    old_chunks = {ref for ref in backend.values if ".chunk." in ref}

    store.set("oauth.chatgpt", "short")

    assert store.get("oauth.chatgpt") == "short"
    assert old_chunks.isdisjoint(backend.values)


def test_deleting_chunked_credential_removes_all_parts() -> None:
    backend = ChunkedMemoryBackend()
    store = SecretStore(backend)
    store.set("oauth.chatgpt", "x" * 900)

    assert store.delete("oauth.chatgpt") is True
    assert backend.values == {}


def test_failed_migration_retains_usable_legacy_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "cli-config.json"
    legacy = {"env": {"STRIX_LLM": "openai/test", "LLM_API_KEY": "legacy-key"}}
    config_path.write_text(json.dumps(legacy), encoding="utf-8")
    monkeypatch.setattr(loader, "_override", config_path)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(
        secret_module,
        "_default_store",
        SecretStore(MemoryBackend(mismatch=True)),
    )
    monkeypatch.setattr(loader, "notify", lambda *_args, **_kwargs: None)

    report = loader.migrate_legacy_config_secrets()

    assert report["failed"] == ["LLM_API_KEY"]
    assert json.loads(config_path.read_text(encoding="utf-8")) == legacy


def test_registered_credentials_are_redacted_from_errors() -> None:
    register_secret("top-secret-token")

    rendered = redact_secrets(
        RuntimeError("authorization: Bearer top-secret-token api_key=top-secret-token")
    )

    assert "top-secret-token" not in rendered
    assert rendered.count("[REDACTED]") >= 1


@pytest.mark.parametrize("ref", ["", "spaces are bad", "../escape", "UPPER/SLASH"])
def test_invalid_references_are_rejected(ref: str) -> None:
    with pytest.raises(ValueError, match="secret reference"):
        SecretStore(MemoryBackend()).get(ref)
