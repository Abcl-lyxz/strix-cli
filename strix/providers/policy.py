"""Signed, data-only Strix quality policy registry."""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from importlib import resources
from pathlib import Path
from typing import Any, cast

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from strix.utils.secret_files import write_secret_text


logger = logging.getLogger(__name__)
POLICY_URL = "https://downloads.strix.ai/provider-policy/v1.json"
_PUBLIC_KEY = base64.b64decode("A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=")
_MAX_BYTES = 2 * 1024 * 1024
_STALE_SECONDS = 24 * 60 * 60
_refresh_lock = threading.Lock()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verify_policy(document: dict[str, Any]) -> dict[str, Any]:
    payload = document.get("payload")
    signature = document.get("signature")
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("Unsupported provider policy document")
    if not isinstance(payload.get("models"), dict) or not isinstance(signature, str):
        raise TypeError("Provider policy document is incomplete")
    try:
        Ed25519PublicKey.from_public_bytes(_PUBLIC_KEY).verify(
            base64.b64decode(signature, validate=True),
            _canonical(cast("dict[str, Any]", payload)),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Provider policy signature is invalid") from exc
    return cast("dict[str, Any]", payload)


def _packaged() -> dict[str, Any]:
    document = json.loads(
        resources.files("strix").joinpath("data/provider_policy.json").read_text(encoding="utf-8")
    )
    return verify_policy(cast("dict[str, Any]", document))


def _cache_path() -> Path:
    return Path.home() / ".strix" / "cache" / "provider-policy.json"


def _read_cache() -> tuple[dict[str, Any], float] | None:
    path = _cache_path()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        return verify_policy(cast("dict[str, Any]", document)), path.stat().st_mtime
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def refresh_policy(*, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch signed data only; provider plugin code is never downloaded."""

    response = requests.get(POLICY_URL, timeout=timeout, allow_redirects=False)
    response.raise_for_status()
    if len(response.content) > _MAX_BYTES:
        raise ValueError("Provider policy exceeds 2 MiB")
    document = response.json()
    if not isinstance(document, dict):
        raise TypeError("Provider policy must be a JSON object")
    payload = verify_policy(cast("dict[str, Any]", document))
    write_secret_text(_cache_path(), json.dumps(document, indent=2) + "\n")
    return payload


def _background_refresh() -> None:
    if not _refresh_lock.acquire(blocking=False):
        return
    try:
        refresh_policy()
    except (OSError, ValueError, requests.RequestException):
        logger.debug(
            "Provider policy refresh failed; retaining last-known-good data", exc_info=True
        )
    finally:
        _refresh_lock.release()


def load_policy() -> dict[str, Any]:
    cached = _read_cache()
    if cached is None:
        return _packaged()
    payload, modified = cached
    if time.time() - modified > _STALE_SECONDS:
        threading.Thread(
            target=_background_refresh, name="strix-policy-refresh", daemon=True
        ).start()
    return payload


def quality_tier(provider_id: str, adapter_id: str, model_id: str) -> str:
    models = load_policy().get("models", {})
    if not isinstance(models, dict):
        return "unknown"
    for key in (f"{provider_id}/{model_id}", f"{adapter_id}/{model_id}"):
        entry = models.get(key)
        if isinstance(entry, dict) and entry.get("quality_tier") in {
            "frontier",
            "strong",
            "standard",
            "economy",
        }:
            return str(entry["quality_tier"])
    return "unknown"


__all__ = ["load_policy", "quality_tier", "refresh_policy", "verify_policy"]
