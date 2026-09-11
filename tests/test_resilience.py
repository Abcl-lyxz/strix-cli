from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from strix.resilience import full_jitter_delay, retry_after_seconds


class _FixedRandom:
    @staticmethod
    def uniform(low: float, high: float) -> float:
        assert low == 0.0
        return high / 2


def test_full_jitter_uses_exponential_cap() -> None:
    assert (
        full_jitter_delay(
            3,
            base_delay=2.0,
            max_delay=30.0,
            random_source=_FixedRandom,
        )
        == 4.0
    )


def test_retry_after_is_never_undercut_by_jitter() -> None:
    assert (
        full_jitter_delay(
            1,
            base_delay=2.0,
            max_delay=30.0,
            retry_after=12.0,
            random_source=_FixedRandom,
        )
        == 12.0
    )


def test_retry_after_parses_seconds_and_http_date() -> None:
    seconds_error = RuntimeError("rate limited")
    seconds_error.response = SimpleNamespace(headers={"Retry-After": "7"})  # type: ignore[attr-defined]
    assert retry_after_seconds(seconds_error) == 7.0

    date_error = RuntimeError("rate limited")
    date_error.response = SimpleNamespace(  # type: ignore[attr-defined]
        headers={"Retry-After": "Wed, 21 Oct 2015 07:28:10 GMT"}
    )
    assert retry_after_seconds(date_error, now=datetime(2015, 10, 21, 7, 28, tzinfo=UTC)) == 10.0


def test_malformed_retry_after_is_ignored() -> None:
    error = RuntimeError("rate limited")
    error.response = SimpleNamespace(headers={"Retry-After": "later"})  # type: ignore[attr-defined]
    assert retry_after_seconds(error) is None
