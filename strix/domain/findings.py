"""Typed finding commands and mutation outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


type FindingClass = Literal["dynamic", "dependency_cve"]


@dataclass(frozen=True, slots=True)
class CreateFinding:
    title: str
    finding_class: FindingClass
    candidate: dict[str, Any]
    fields: dict[str, Any]
    agent_id: str | None = None
    agent_name: str | None = None


@dataclass(frozen=True, slots=True)
class ReviseFinding:
    report_id: str
    changes: dict[str, Any]
    reason: str
    agent_id: str | None = None
    agent_name: str | None = None


@dataclass(frozen=True, slots=True)
class FindingMutation:
    status: Literal["created", "updated", "duplicate", "missing", "unchanged", "failed"]
    report_id: str | None = None
    finding: dict[str, Any] | None = None
    duplicate_id: str | None = None
    duplicate_title: str = ""
    confidence: float = 0.0
    reason: str = ""
    error: str = ""
