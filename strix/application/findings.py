"""Finding creation and revision use cases."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from strix.domain.findings import CreateFinding, FindingMutation, ReviseFinding


if TYPE_CHECKING:
    from strix.ports.reporting import DuplicateDetector, ReportRepository


logger = logging.getLogger(__name__)


class FindingService:
    """Own deduplication and persistence independently of SDK tool schemas."""

    def __init__(
        self, repository: ReportRepository, duplicate_detector: DuplicateDetector
    ) -> None:
        self.repository = repository
        self.duplicate_detector = duplicate_detector

    async def create(self, command: CreateFinding) -> FindingMutation:
        try:
            existing = self.repository.get_existing_vulnerabilities()
            duplicate = await self.duplicate_detector(
                command.candidate, existing, self.repository
            )
            if duplicate.get("is_duplicate"):
                duplicate_id = str(duplicate.get("duplicate_id") or "")
                duplicate_title = next(
                    (
                        str(item.get("title") or "Unknown")
                        for item in existing
                        if item.get("id") == duplicate_id
                    ),
                    "",
                )
                return FindingMutation(
                    status="duplicate",
                    duplicate_id=duplicate_id,
                    duplicate_title=duplicate_title,
                    confidence=float(duplicate.get("confidence") or 0.0),
                    reason=str(duplicate.get("reason") or ""),
                )
            fields: dict[str, Any] = {
                **command.fields,
                "finding_class": command.finding_class,
                "agent_id": command.agent_id,
                "agent_name": command.agent_name,
            }
            if command.finding_class == "dynamic":
                fields.pop("finding_class")
            report_id = self.repository.add_vulnerability_report(**fields)
            return FindingMutation(status="created", report_id=report_id)
        except Exception as exc:
            logger.exception("finding creation failed")
            return FindingMutation(status="failed", error=str(exc))

    def revise(self, command: ReviseFinding) -> FindingMutation:
        try:
            updated = self.repository.update_vulnerability_report(
                command.report_id,
                command.changes,
                update_reason=command.reason,
                updated_by_agent_id=command.agent_id,
                updated_by_agent_name=command.agent_name,
            )
        except Exception as exc:
            logger.exception("finding revision failed")
            return FindingMutation(status="failed", report_id=command.report_id, error=str(exc))
        if updated is not None:
            return FindingMutation(
                status="updated", report_id=command.report_id, finding=updated
            )
        known = {
            str(item.get("id")) for item in self.repository.get_existing_vulnerabilities()
        }
        return FindingMutation(
            status="unchanged" if command.report_id in known else "missing",
            report_id=command.report_id,
        )
