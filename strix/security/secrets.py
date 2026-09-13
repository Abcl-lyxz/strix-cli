"""Cross-platform storage for reusable Strix credentials.

Only opaque references are written to Strix JSON files. Secret values live in
the operating-system credential service: Credential Manager on Windows,
Keychain on macOS, and Secret Service (through ``secret-tool``) on Linux.
"""

from __future__ import annotations

import ctypes
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
from contextlib import contextmanager, suppress
from ctypes import wintypes
from typing import TYPE_CHECKING, Any, Protocol, cast


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable
    from pathlib import Path


_SERVICE = "strix-cli"
_REF_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,191}$")
_CHUNK_MARKER = "strix-secret-chunks-v1:"
_known_values: set[str] = set()
_known_values_lock = threading.Lock()


def _windows_api() -> Any:
    module: Any = ctypes
    return module.WinDLL("advapi32", use_last_error=True)


def _windows_last_error() -> int:
    module: Any = ctypes
    return int(module.get_last_error())


def _verification_failed() -> None:
    raise SecretStoreUnavailableError("credential verification failed after writing")


def _notify_credential_required(backend_name: str) -> None:
    # Imported lazily because the notification service itself uses secret
    # redaction from this module.
    notifications: Any = importlib.import_module("strix.notifications")
    notifications.notify(
        "security.credential_required",
        title="Persistent credential storage is unavailable",
        detail=f"{backend_name} is unavailable; use an environment variable for this session.",
        severity="warning",
        dedupe_key="credential-store:unavailable",
    )


class SecretStoreUnavailableError(RuntimeError):
    """Raised when the host has no usable OS credential service."""


class SecretBackend(Protocol):
    @property
    def available(self) -> bool: ...

    @property
    def name(self) -> str: ...

    def get(self, ref: str) -> str | None: ...

    def set(self, ref: str, value: str) -> None: ...

    def delete(self, ref: str) -> bool: ...


def _validate_ref(ref: str) -> str:
    normalized = ref.strip().lower()
    if not _REF_PATTERN.fullmatch(normalized):
        raise ValueError("secret reference must use letters, numbers, '.', '_', ':', or '-'")
    return normalized


def _remember(value: str | None) -> None:
    if value and len(value) >= 4:
        with _known_values_lock:
            _known_values.add(value)


def register_secret(value: str | None) -> None:
    """Register a process-only credential for centralized output redaction."""
    _remember(value)


def redact_secrets(value: object, additional: Iterable[str] = ()) -> str:
    """Return text with every credential value known to this process removed."""
    text = str(value)
    with _known_values_lock:
        candidates = set(_known_values)
    candidates.update(secret for secret in additional if secret and len(secret) >= 4)
    for secret in sorted(candidates, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    # Last-resort protection for common bearer/key forms in provider errors.
    text = re.sub(
        r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)([?&]token=)[^\s&\"]+", r"\1[REDACTED]", text)
    return re.sub(
        r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*)[^\s,;]+",
        r"\1[REDACTED]",
        text,
    )


def redact_value(value: Any) -> Any:
    """Redact strings without damaging structured JSON or mutating the source."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [redact_value(item) for item in cast("list[object]", value)]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in cast("dict[str, Any]", value).items()}
    return value


class _CommandBackend:
    executable = ""
    backend_name = ""

    @property
    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    @property
    def name(self) -> str:
        return self.backend_name

    @staticmethod
    def _run(args: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )


class MacOSKeychainBackend(_CommandBackend):
    executable = "/usr/bin/security"
    backend_name = "macOS Keychain"

    def get(self, ref: str) -> str | None:
        result = self._run(
            [self.executable, "find-generic-password", "-s", _SERVICE, "-a", ref, "-w"]
        )
        return result.stdout.rstrip("\r\n") if result.returncode == 0 else None

    def set(self, ref: str, value: str) -> None:
        result = self._run(
            [
                self.executable,
                "add-generic-password",
                "-U",
                "-s",
                _SERVICE,
                "-a",
                ref,
                "-w",
            ],
            input_text=value,
        )
        if result.returncode != 0:
            raise SecretStoreUnavailableError("macOS Keychain rejected the credential")

    def delete(self, ref: str) -> bool:
        result = self._run([self.executable, "delete-generic-password", "-s", _SERVICE, "-a", ref])
        return result.returncode == 0


class LinuxSecretServiceBackend(_CommandBackend):
    executable = "secret-tool"
    backend_name = "Linux Secret Service"

    def get(self, ref: str) -> str | None:
        result = self._run([self.executable, "lookup", "service", _SERVICE, "ref", ref])
        return result.stdout.rstrip("\r\n") if result.returncode == 0 else None

    def set(self, ref: str, value: str) -> None:
        result = self._run(
            [
                self.executable,
                "store",
                "--label",
                f"Strix credential: {ref}",
                "service",
                _SERVICE,
                "ref",
                ref,
            ],
            input_text=value,
        )
        if result.returncode != 0:
            raise SecretStoreUnavailableError("Linux Secret Service rejected the credential")

    def delete(self, ref: str) -> bool:
        result = self._run([self.executable, "clear", "service", _SERVICE, "ref", ref])
        return result.returncode == 0


class WindowsCredentialBackend:
    """Generic credentials stored through the Win32 Credential API."""

    _CRED_TYPE_GENERIC = 1
    _CRED_PERSIST_LOCAL_MACHINE = 2
    backend_name = "Windows Credential Manager"
    # CRED_MAX_CREDENTIAL_BLOB_SIZE is 2560 bytes on supported Windows
    # versions. Leave room for platform variation and use generated chunks for
    # larger OAuth/session payloads.
    max_value_bytes = 2_400

    @property
    def available(self) -> bool:
        return os.name == "nt"

    @property
    def name(self) -> str:
        return self.backend_name

    @staticmethod
    def encoded_size(value: str) -> int:
        return len(value.encode("utf-16-le"))

    @staticmethod
    def _target(ref: str) -> str:
        return f"{_SERVICE}:{ref}"

    @staticmethod
    def _types() -> tuple[type[ctypes.Structure], type[ctypes.Structure]]:
        class CredentialAttribute(ctypes.Structure):
            _fields_ = [
                ("Keyword", wintypes.LPWSTR),
                ("Flags", wintypes.DWORD),
                ("ValueSize", wintypes.DWORD),
                ("Value", ctypes.POINTER(ctypes.c_ubyte)),
            ]

        class Credential(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.POINTER(CredentialAttribute)),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        return CredentialAttribute, Credential

    def get(self, ref: str) -> str | None:
        _attribute, credential_type = self._types()
        pointer = ctypes.POINTER(credential_type)()
        advapi32 = _windows_api()
        advapi32.CredReadW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(credential_type)),
        ]
        advapi32.CredReadW.restype = wintypes.BOOL
        if not advapi32.CredReadW(
            self._target(ref), self._CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)
        ):
            return None
        try:
            credential = pointer.contents
            blob = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
            return blob.decode("utf-16-le")
        finally:
            advapi32.CredFree(pointer)

    def set(self, ref: str, value: str) -> None:
        _attribute, credential_type = self._types()
        blob = value.encode("utf-16-le")
        buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        credential = credential_type()
        credential.Type = self._CRED_TYPE_GENERIC
        credential.TargetName = self._target(ref)
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        credential.Persist = self._CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = ref
        advapi32 = _windows_api()
        advapi32.CredWriteW.argtypes = [
            ctypes.POINTER(credential_type),
            wintypes.DWORD,
        ]
        advapi32.CredWriteW.restype = wintypes.BOOL
        if not advapi32.CredWriteW(ctypes.byref(credential), 0):
            raise SecretStoreUnavailableError(
                f"Windows Credential Manager failed with code {_windows_last_error()}"
            )

    def delete(self, ref: str) -> bool:
        advapi32 = _windows_api()
        advapi32.CredDeleteW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        advapi32.CredDeleteW.restype = wintypes.BOOL
        return bool(advapi32.CredDeleteW(self._target(ref), self._CRED_TYPE_GENERIC, 0))


class SecretStore:
    """Validated, verification-first facade over the platform credential service."""

    def __init__(self, backend: SecretBackend | None = None) -> None:
        self._backend = backend or _platform_backend()

    @property
    def available(self) -> bool:
        return self._backend.available

    @property
    def backend_name(self) -> str:
        return self._backend.name

    def get(self, ref: str) -> str | None:
        if not self.available:
            return None
        normalized = _validate_ref(ref)
        raw = self._backend.get(normalized)
        value = self._decode_value(normalized, raw)
        _remember(value)
        return value

    def set(self, ref: str, value: str) -> None:
        normalized = _validate_ref(ref)
        if not value:
            raise ValueError("secret value cannot be empty")
        if not self.available:
            _notify_credential_required(self.backend_name)
            raise SecretStoreUnavailableError(
                "No supported OS keychain is available; use an environment variable "
                "for this session"
            )
        previous = self._backend.get(normalized)
        previous_chunks = self._chunk_refs(normalized, previous)
        max_bytes = cast("object", getattr(self._backend, "max_value_bytes", None))
        raw_encoded_size = cast("object", getattr(self._backend, "encoded_size", None))
        encoded_size: Callable[[str], int] = (
            cast("Callable[[str], int]", raw_encoded_size)
            if callable(raw_encoded_size)
            else lambda item: len(item.encode())
        )
        if isinstance(max_bytes, int) and encoded_size(value) > max_bytes:
            self._set_chunked(
                normalized,
                value,
                max_bytes=max_bytes,
                encoded_size=encoded_size,
                previous=previous,
                previous_chunks=previous_chunks,
            )
            _remember(value)
            return

        self._backend.set(normalized, value)
        try:
            verified = self._backend.get(normalized)
        except Exception as exc:
            self._restore_raw(normalized, previous)
            raise SecretStoreUnavailableError(
                "credential verification failed after writing"
            ) from exc
        if verified != value:
            # Do not leave an unverifiable partial credential behind. Callers
            # keep their legacy plaintext until this method returns, so a
            # failed migration remains usable and can be retried safely.
            self._restore_raw(normalized, previous)
            raise SecretStoreUnavailableError("credential verification failed after writing")
        self._delete_refs(previous_chunks)
        _remember(value)

    def delete(self, ref: str) -> bool:
        if not self.available:
            return False
        normalized = _validate_ref(ref)
        raw = self._backend.get(normalized)
        chunks = self._chunk_refs(normalized, raw)
        removed = self._backend.delete(normalized)
        return self._delete_refs(chunks) or removed

    def _set_chunked(
        self,
        ref: str,
        value: str,
        *,
        max_bytes: int,
        encoded_size: Any,
        previous: str | None,
        previous_chunks: list[str],
    ) -> None:
        generation = uuid.uuid4().hex
        parts = _split_for_backend(value, max_bytes=max_bytes, encoded_size=encoded_size)
        prefix = _chunk_prefix(ref)
        refs = [f"{prefix}{generation}.{index}" for index in range(len(parts))]
        marker = _CHUNK_MARKER + json.dumps(
            {"generation": generation, "parts": len(parts)}, separators=(",", ":")
        )
        if encoded_size(marker) > max_bytes:
            raise SecretStoreUnavailableError("credential reference metadata is too large")

        try:
            for chunk_ref, part in zip(refs, parts, strict=True):
                self._backend.set(chunk_ref, part)
                if self._backend.get(chunk_ref) != part:
                    _verification_failed()
            self._backend.set(ref, marker)
            if self._backend.get(ref) != marker or self._decode_value(ref, marker) != value:
                _verification_failed()
        except Exception as exc:
            self._delete_refs(refs)
            self._restore_raw(ref, previous)
            if isinstance(exc, SecretStoreUnavailableError):
                raise
            raise SecretStoreUnavailableError(
                "credential verification failed after writing"
            ) from exc

        self._delete_refs(previous_chunks)

    def _decode_value(self, ref: str, raw: str | None) -> str | None:
        refs = self._chunk_refs(ref, raw)
        if raw is None or not raw.startswith(_CHUNK_MARKER):
            return raw
        if not refs:
            return None
        parts = [self._backend.get(chunk_ref) for chunk_ref in refs]
        if any(part is None for part in parts):
            return None
        return "".join(part for part in parts if part is not None)

    @staticmethod
    def _chunk_refs(ref: str, raw: str | None) -> list[str]:
        if raw is None or not raw.startswith(_CHUNK_MARKER):
            return []
        try:
            payload = json.loads(raw.removeprefix(_CHUNK_MARKER))
            generation = payload["generation"]
            count = payload["parts"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return []
        prefix = _chunk_prefix(ref)
        if (
            not isinstance(generation, str)
            or re.fullmatch(r"[0-9a-f]{32}", generation) is None
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not 1 <= count <= 100_000
        ):
            return []
        return [f"{prefix}{generation}.{index}" for index in range(count)]

    def _restore_raw(self, ref: str, previous: str | None) -> None:
        with suppress(Exception):
            if previous is None:
                self._backend.delete(ref)
            else:
                self._backend.set(ref, previous)

    def _delete_refs(self, refs: Iterable[str]) -> bool:
        removed = False
        for chunk_ref in refs:
            with suppress(Exception):
                removed = self._backend.delete(chunk_ref) or removed
        return removed


def _split_for_backend(value: str, *, max_bytes: int, encoded_size: Any) -> list[str]:
    """Split without bisecting Unicode while respecting backend byte limits."""
    parts: list[str] = []
    current = ""
    for character in value:
        candidate = current + character
        if current and encoded_size(candidate) > max_bytes:
            parts.append(current)
            current = character
        else:
            current = candidate
        if encoded_size(current) > max_bytes:
            raise SecretStoreUnavailableError("credential contains an unsupported character")
    if current:
        parts.append(current)
    return parts


def _chunk_prefix(ref: str) -> str:
    # Preserve enough room for a UUID, separator, and a generous decimal part
    # index while keeping generated references within the validated limit.
    return f"{ref[:145]}.chunk."


def _platform_backend() -> SecretBackend:
    if os.name == "nt":
        return WindowsCredentialBackend()
    if sys.platform == "darwin":
        return MacOSKeychainBackend()
    return LinuxSecretServiceBackend()


_default_store: SecretStore | None = None


def get_secret_store() -> SecretStore:
    global _default_store  # noqa: PLW0603
    if _default_store is None:
        _default_store = SecretStore()
    return _default_store


@contextmanager
def interprocess_lock(path: Path) -> Generator[None, None, None]:
    """Portable advisory lock used while rotating single-use credentials."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        handle.seek(0)
        if handle.read(1) == b"":
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl: Any = importlib.import_module("fcntl")
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            handle.seek(0)
            if os.name == "nt":
                msvcrt = importlib.import_module("msvcrt")
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl = importlib.import_module("fcntl")
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
