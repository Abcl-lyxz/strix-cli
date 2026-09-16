"""Reporting ports kept independent from tool and storage implementations."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol


type DuplicateDetector = Callable[
    [dict[str, Any], list[dict[str, Any]], "UsageRepository"],
    Awaitable[dict[str, Any]],
]


class FindingRepository(Protocol):
    def add_vulnerability_report(self, **fields: Any) -> str: ...

    def update_vulnerability_report(
        self,
        report_id: str,
        fields: dict[str, Any],
        **metadata: Any,
    ) -> dict[str, Any] | None: ...

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]: ...


class UsageRepository(Protocol):
    def record_sdk_usage(
        self,
        *,
        agent_id: str,
        usage: Any | None,
        agent_name: str | None = None,
        model: str | None = None,
        route: str | None = None,
    ) -> None: ...

    def record_observed_llm_cost(self, cost: float) -> None: ...

    def get_total_llm_cost(self) -> float: ...


class ReportRepository(FindingRepository, UsageRepository, Protocol):
    """Combined report persistence used while findings consume LLM deduplication."""
