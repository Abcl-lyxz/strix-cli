"""Read-only reporting tool adapters and projections."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from strix.tools.nullish import clean_optional
from strix.tools.reporting.context import caller_identity as _caller_identity
from strix.tools.reporting.context import report_repository as _report_state_from_context


if TYPE_CHECKING:
    from strix.ports.reporting import ReportRepository


logger = logging.getLogger(__name__)


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "none": 5,
}
_VALID_SEVERITIES = frozenset(_SEVERITY_ORDER)
_VALID_FINDING_CLASSES = frozenset({"dynamic", "dependency_cve"})
_REPORT_DESCRIPTION_PREVIEW_CHARS = 280

# Compact, listing-safe fields — no full bodies / PoC code / evidence.
_REPORT_SUMMARY_FIELDS = (
    "id",
    "title",
    "severity",
    "cvss",
    "confidence",
    "finding_class",
    "cve",
    "cwe",
    "target",
    "endpoint",
    "method",
    "fix_effort",
    "agent_name",
    "timestamp",
)


def _report_severity_rank(report: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(str(report.get("severity", "")).lower(), 99)


def _report_matches_filters(
    report: dict[str, Any],
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
) -> bool:
    if severity and str(report.get("severity", "")).lower() != severity:
        return False
    if finding_class and str(report.get("finding_class", "dynamic")).lower() != finding_class:
        return False
    if target:
        target_lower = target.lower()
        haystack = f"{report.get('target', '')} {report.get('endpoint', '')}".lower()
        if target_lower not in haystack:
            return False
    if search:
        search_lower = search.lower()
        title_match = search_lower in str(report.get("title", "")).lower()
        desc_match = search_lower in str(report.get("description", "")).lower()
        if not (title_match or desc_match):
            return False
    return True


def _mark_authorship(
    entry: dict[str, Any], report: dict[str, Any], caller_agent_id: str | None
) -> dict[str, Any]:
    """Flag whether ``report`` was filed by the agent making this call."""
    if caller_agent_id is not None and report.get("agent_id") == caller_agent_id:
        entry["by_you"] = True
    return entry


def _to_report_summary_entry(
    report: dict[str, Any], caller_agent_id: str | None = None
) -> dict[str, Any]:
    entry = {
        field: report[field] for field in _REPORT_SUMMARY_FIELDS if report.get(field) is not None
    }
    description = str(report.get("description", "")).strip()
    if description:
        if len(description) > _REPORT_DESCRIPTION_PREVIEW_CHARS:
            entry["description_preview"] = (
                f"{description[:_REPORT_DESCRIPTION_PREVIEW_CHARS].rstrip()}..."
            )
        else:
            entry["description_preview"] = description
    return _mark_authorship(entry, report, caller_agent_id)


def _severity_counts(reports: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for report in reports:
        sev = str(report.get("severity", "")).lower() or "none"
        counts[sev] = counts.get(sev, 0) + 1
    return {sev: counts[sev] for sev in _SEVERITY_ORDER if sev in counts}


async def _run_report_reader(fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except (ImportError, AttributeError) as e:
        logger.exception("report reader failed")
        return {"success": False, "error": f"Failed to read reports: {e!s}"}


def _do_list_reports(
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
    include_details: bool,
    caller_agent_id: str | None = None,
    report_state: ReportRepository | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    severity = (clean_optional(severity) or "").lower() or None
    if severity and severity not in _VALID_SEVERITIES:
        errors.append(
            f"Invalid severity: {severity!r}. Must be one of: {sorted(_VALID_SEVERITIES)}"
        )
    finding_class = (clean_optional(finding_class) or "").lower() or None
    if finding_class and finding_class not in _VALID_FINDING_CLASSES:
        errors.append(
            f"Invalid finding_class: {finding_class!r}. "
            f"Must be one of: {sorted(_VALID_FINDING_CLASSES)}"
        )
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    if report_state is None:
        return {
            "success": True,
            "reports": [],
            "filtered_count": 0,
            "total_count": 0,
            "severity_counts": {},
            "warning": "Report state unavailable - no reports have been filed yet",
        }

    all_reports = report_state.get_existing_vulnerabilities()
    matched = [
        r
        for r in all_reports
        if _report_matches_filters(
            r,
            severity=severity,
            finding_class=finding_class,
            target=clean_optional(target),
            search=clean_optional(search),
        )
    ]
    matched.sort(key=lambda r: (_report_severity_rank(r), str(r.get("id", ""))))

    reports = [
        _mark_authorship(dict(r), r, caller_agent_id)
        if include_details
        else _to_report_summary_entry(r, caller_agent_id)
        for r in matched
    ]
    return {
        "success": True,
        "reports": reports,
        "filtered_count": len(reports),
        "total_count": len(all_reports),
        "severity_counts": _severity_counts(all_reports),
    }


def _do_get_report(
    report_id: str,
    caller_agent_id: str | None = None,
    report_state: ReportRepository | None = None,
) -> dict[str, Any]:
    report_id = (report_id or "").strip()
    if not report_id:
        return {"success": False, "error": "report_id cannot be empty", "report": None}

    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
            "report": None,
        }

    for report in report_state.get_existing_vulnerabilities():
        if report.get("id") == report_id:
            return {
                "success": True,
                "report": _mark_authorship(dict(report), report, caller_agent_id),
            }
    return {
        "success": False,
        "error": f"Report with id '{report_id}' not found",
        "report": None,
    }


@function_tool(timeout=30)
async def list_reports(
    ctx: RunContextWrapper,
    severity: str | None = None,
    finding_class: str | None = None,
    target: str | None = None,
    search: str | None = None,
    include_details: bool = False,
) -> str:
    """List vulnerability reports filed so far in this scan — metadata-first.

    **For the orchestrator / root agent.** This is an orchestration tool
    for tracking scan-wide coverage and assembling the final report — leaf
    / specialist agents do their own testing and file findings; they should
    NOT call this. If you are a subagent, ignore it and focus on your task.

    Reports are shared across **every** agent in the scan, so this returns
    findings filed by any agent (root or child), not just your own. As the
    root agent, use it to track progress, avoid dispatching work on
    already-covered ground, reason about attack-chaining across confirmed
    findings, and build the ``finish_scan`` executive summary.

    By default each entry is compact: ``id``, ``title``, ``severity``,
    ``cvss``, ``confidence``, ``finding_class``, ``cve`` / ``cwe``,
    ``target`` / ``endpoint``, ``fix_effort``, ``agent_name`` (who filed it), ``timestamp``,
    plus a 280-char ``description_preview``. Entries you filed yourself are
    flagged ``by_you: true``. The response also carries
    ``total_count`` and ``severity_counts`` (counts per severity across all
    reports, ignoring filters). Set ``include_details=True`` for full report
    bodies (PoC, evidence, remediation, code_locations) — token-expensive;
    prefer ``get_report`` to drill into a single finding.

    Filters compose (all must match): ``severity`` and ``finding_class``
    match exactly, ``target`` is a substring match against target/endpoint,
    and ``search`` is a substring match against title/description. Results
    are ordered by severity (critical -> info), then report id.

    This is read-only — it never files or dedupes anything.

    Args:
        severity: Filter to one of ``critical`` / ``high`` / ``medium`` /
            ``low`` / ``info`` / ``none``.
        finding_class: Filter to ``dynamic`` (PoC-backed) or
            ``dependency_cve`` (known-CVE supply-chain).
        target: Substring match against a report's target / endpoint.
        search: Substring match against title and description.
        include_details: When False (default) entries are compact; when
            True full report bodies are returned.
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(
            _do_list_reports,
            severity=severity,
            finding_class=finding_class,
            target=target,
            search=search,
            include_details=include_details,
            caller_agent_id=caller_agent_id,
            report_state=_report_state_from_context(ctx),
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_report(ctx: RunContextWrapper, report_id: str) -> str:
    """Fetch one vulnerability report by its id (e.g. ``vuln-0001``).

    Returns the full report body — description, impact, technical analysis,
    PoC, evidence, remediation, CVSS breakdown, and any ``code_locations``.
    Use ``list_reports`` first to find ids; this is the cheap way to read a
    single finding in full without pulling every body.

    Read-only.

    Args:
        report_id: Report id from ``list_reports`` or a
            ``create_vulnerability_report`` / ``create_dependency_report``
            response (format ``vuln-NNNN``).
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(
            _do_get_report,
            report_id,
            caller_agent_id,
            _report_state_from_context(ctx),
        ),
        ensure_ascii=False,
        default=str,
    )
