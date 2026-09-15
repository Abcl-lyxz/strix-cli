"""Stable, sanitized failures shared by routing, execution, and interfaces."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Literal

from strix.llm.errors import classify_model_failure
from strix.security import redact_secrets


ErrorCategory = Literal[
    "provider_authentication",
    "provider_billing",
    "provider_throttled",
    "provider_transient",
    "context_overflow",
    "provider_policy",
    "provider_incompatible",
    "model_malformed",
    "tool_validation",
    "tool_timeout",
    "sandbox",
    "browser_proxy",
    "uncertain_side_effect",
    "fatal",
]


@dataclass(frozen=True, slots=True)
class ErrorEnvelope:
    """Machine-readable error with no credentials or provider response bodies."""

    error_id: str
    category: ErrorCategory
    retryable: bool
    safe_to_replay: bool
    attempt: int
    retry_after_seconds: float | None
    detail: str
    action: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def error_envelope(
    error: BaseException,
    *,
    attempt: int = 1,
    retry_after: float | None = None,
    safe_to_replay: bool = True,
    category_hint: ErrorCategory | None = None,
) -> ErrorEnvelope:
    """Classify and sanitize ``error`` for persistence and UI display."""
    kind = classify_model_failure(error)
    text = str(error).lower()
    status = getattr(error, "status_code", None)
    category: ErrorCategory
    action: str | None
    if category_hint is not None:
        category = category_hint
        action = {
            "tool_validation": "Correct the tool arguments and try once more.",
            "tool_timeout": "Inspect the job state before restarting it.",
            "sandbox": "Run sandbox preflight and inspect the container diagnostics.",
            "browser_proxy": "Inspect browser/proxy health and restart the read-only operation.",
            "uncertain_side_effect": "Inspect the target state before deciding whether to retry.",
        }.get(category_hint)
    elif kind == "authentication":
        category = "provider_authentication"
        action = "Update the route credentials, then test the connection."
    elif kind == "billing":
        category = "provider_billing"
        action = "Add provider credit or select another healthy route."
    elif kind == "transient" and (status == 429 or "rate limit" in text or "throttl" in text):
        category = "provider_throttled"
        action = None
    elif kind == "transient":
        category = "provider_transient"
        action = None
    elif kind == "context":
        category = "context_overflow"
        action = "Compact the session or configure the model's real context limit."
    elif kind == "policy":
        category = "provider_policy"
        action = "Review the provider policy response; Strix will not route around it."
    elif kind == "incompatible":
        category = "provider_incompatible"
        action = "Choose a model that supports the required tools and transport."
    elif kind == "malformed":
        category = "model_malformed"
        action = "Retry with repaired model history."
    else:
        category = "fatal"
        action = "Open local diagnostics using the error ID."
    detail = redact_secrets(str(error) or type(error).__name__)
    digest = hashlib.sha256(f"{category}:{type(error).__name__}:{detail}".encode()).hexdigest()[:12]
    retryable = category in {
        "provider_throttled",
        "provider_transient",
        "context_overflow",
        "tool_timeout",
        "browser_proxy",
    }
    return ErrorEnvelope(
        error_id=f"strix-{digest}",
        category=category,
        retryable=retryable,
        safe_to_replay=safe_to_replay,
        attempt=max(1, attempt),
        retry_after_seconds=retry_after,
        detail=detail,
        action=action,
    )


__all__ = ["ErrorCategory", "ErrorEnvelope", "error_envelope"]
