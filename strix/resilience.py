"""Small, shared retry primitives for transient external failures."""

from __future__ import annotations

import random
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any


def retry_after_seconds(error: BaseException, *, now: datetime | None = None) -> float | None:
    """Extract a non-negative ``Retry-After`` delay from an HTTP-style exception."""
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return None
    value = str(raw).strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=UTC)
    current = now or datetime.now(UTC)
    return max(0.0, (target - current).total_seconds())


def full_jitter_delay(
    attempt: int,
    *,
    base_delay: float,
    max_delay: float,
    retry_after: float | None = None,
    random_source: Any = random,
) -> float:
    """Return bounded exponential backoff with full jitter.

    ``attempt`` is one-based. A provider supplied ``Retry-After`` is a floor,
    so a client never retries earlier than requested by the server.
    """
    exponent = max(0, attempt - 1)
    cap = max(0.0, min(max_delay, max(0.0, base_delay) * float(2**exponent)))
    jittered = float(random_source.uniform(0.0, cap)) if cap > 0 else 0.0
    if retry_after is None:
        return jittered
    return max(jittered, 0.0, retry_after)
