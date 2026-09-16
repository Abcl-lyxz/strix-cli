"""Finding revision validation and use-case orchestration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from strix.application.findings import FindingService
from strix.domain.findings import ReviseFinding
from strix.report.dedupe import check_duplicate
from strix.tools.nullish import clean_optional
from strix.tools.reporting.validation import (
    _MAX_CONTEXTUAL_REASONING_CHARS,
    _VALID_CONFIDENCE,
    _VALID_FIX_EFFORT,
    _calculate_cvss,
    _normalize_code_locations,
    _normalize_http_exchange_ids,
    _validate_code_locations,
    _validate_cvss_breakdown,
    _validate_fix_verification,
    _validate_identifiers,
)


if TYPE_CHECKING:
    from strix.ports.reporting import ReportRepository


logger = logging.getLogger(__name__)


def _finding_class_of(report: dict[str, Any]) -> str:
    """Resolve the class of a stored finding.

    A finding filed before ``finding_class`` was persisted still carries the
    metadata of its class. A record with dependency metadata is a dependency
    finding even when the field is absent, so read the metadata before falling
    back to dynamic.
    """
    declared = str(report.get("finding_class") or "").lower()
    if declared:
        return declared
    if report.get("dependency_metadata"):
        return "dependency_cve"
    return "dynamic"


_UPDATE_TEXT_FIELDS = (
    "title",
    "description",
    "impact",
    "target",
    "technical_analysis",
    "poc_description",
    "poc_script_code",
    "remediation_steps",
    "evidence",
    "assumptions",
    "counterevidence",
    "confidence_rationale",
    "severity_change_conditions",
    "endpoint",
    "method",
    "fix_verification",
    "fix_pr_body",
    "contextual_cvss_reasoning",
)


def _collect_update_changes(  # noqa: PLR0912, PLR0915
    fields: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Validate the fields a revision replaces and return them with any errors."""
    errors: list[str] = []
    changes: dict[str, Any] = {}

    for name in _UPDATE_TEXT_FIELDS:
        value = clean_optional(fields.get(name))
        if value is not None:
            changes[name] = value

    confidence = clean_optional(fields.get("confidence"))
    if confidence is not None:
        confidence = confidence.lower()
        if confidence not in _VALID_CONFIDENCE:
            errors.append(
                f"Invalid confidence: {confidence!r}. Must be one of: {sorted(_VALID_CONFIDENCE)}"
            )
        else:
            changes["confidence"] = confidence

    fix_effort = clean_optional(fields.get("fix_effort"))
    if fix_effort is not None:
        fix_effort = fix_effort.lower()
        if fix_effort not in _VALID_FIX_EFFORT:
            errors.append(
                f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
            )
        else:
            changes["fix_effort"] = fix_effort

    breakdown = fields.get("cvss_breakdown")
    if breakdown is not None:
        breakdown_errors = _validate_cvss_breakdown(breakdown)
        errors.extend(breakdown_errors)
        if not breakdown_errors:
            try:
                cvss_score, severity, _vector = _calculate_cvss(breakdown)
            except ValueError as exc:
                errors.append(str(exc))
            else:
                # The rating belongs to the vector, so a revised vector carries
                # its own score and severity rather than leaving the old ones.
                changes["cvss_breakdown"] = breakdown
                changes["cvss"] = cvss_score
                changes["severity"] = severity

    raw_locations = fields.get("code_locations")
    locations = _normalize_code_locations(raw_locations)
    if locations:
        errors.extend(_validate_code_locations(locations))
        errors.extend(_validate_fix_verification(locations, changes.get("fix_verification")))
        changes["code_locations"] = locations
    elif raw_locations:
        errors.append(
            "code_locations were dropped as unusable - every location needs a relative "
            "'file' and an integer 'start_line'"
        )

    cve, cwe, identifier_errors = _validate_identifiers(
        clean_optional(fields.get("cve")), clean_optional(fields.get("cwe"))
    )
    errors.extend(identifier_errors)
    if cve:
        changes["cve"] = cve
    if cwe:
        changes["cwe"] = cwe

    raw_http_exchange_ids = fields.get("http_exchange_ids")
    http_exchange_ids, http_exchange_errors = _normalize_http_exchange_ids(raw_http_exchange_ids)
    errors.extend(http_exchange_errors)
    if raw_http_exchange_ids is not None and not http_exchange_errors:
        changes["http_exchange_ids"] = http_exchange_ids or []

    return changes, errors


# Evidence that only a dynamic finding carries. A dependency finding describes a
# package, not a request against an endpoint.
_DYNAMIC_ONLY_UPDATE_FIELDS = (
    "endpoint",
    "method",
    "poc_description",
    "poc_script_code",
    "http_exchange_ids",
)

# A dependency finding is rated in the context of the codebase that pins it, and
# that rating is only shown with the reasoning behind it.
_DEPENDENCY_ONLY_UPDATE_FIELDS = ("contextual_cvss_reasoning",)


def _reject_cross_class_revision(
    report_id: str,
    matched_class: str,
    offending: list[str],
) -> dict[str, Any]:
    logger.info(
        "Revision of %s carries fields (%s) a %s finding does not hold; rejecting",
        report_id,
        ", ".join(offending),
        matched_class,
    )
    return {
        "success": False,
        "error": (
            f"Report '{report_id}' is a {matched_class} finding, so it cannot carry "
            f"{', '.join(offending)}. File your proof as its own vulnerability report "
            "instead of writing it onto this one."
        ),
        "report_id": report_id,
        "finding_class": matched_class,
        "rejected_fields": offending,
    }


def _rate_dependency_revision(
    report_id: str,
    matched: dict[str, Any],
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    """Turn a replacement ``cvss_breakdown`` into the contextual rating of a dependency.

    A dependency record keeps its rating as ``cvss``/``severity`` plus the
    contextual breakdown, vector and reasoning inside ``dependency_metadata``.
    The package identity in that metadata is copied over untouched. A new
    breakdown needs its own reasoning. The reasoning alone can be corrected
    when the record already carries the breakdown it explains.
    """
    breakdown = changes.pop("cvss_breakdown", None)
    reasoning = changes.pop("contextual_cvss_reasoning", None)
    if breakdown is None and reasoning is None:
        return None

    metadata = dict(matched.get("dependency_metadata") or {})
    if breakdown is None and not metadata.get("contextual_cvss_breakdown"):
        return {
            "success": False,
            "error": "Validation failed",
            "errors": [
                "cvss_breakdown is required: this dependency finding carries no "
                "contextual rating yet, so contextual_cvss_reasoning has nothing to explain"
            ],
            "report_id": report_id,
        }
    if reasoning is None:
        return {
            "success": False,
            "error": "Validation failed",
            "errors": [
                "contextual_cvss_reasoning is required: a dependency finding is re-rated "
                "with the cvss_breakdown observed in this codebase together with the "
                "reasoning a reader can check"
            ],
            "report_id": report_id,
        }

    if breakdown is not None:
        score, _severity, vector = _calculate_cvss(breakdown)
        metadata["contextual_cvss_breakdown"] = breakdown
        metadata["contextual_cvss_score"] = score
        metadata["contextual_cvss_vector"] = vector
    metadata["contextual_cvss_reasoning"] = reasoning[:_MAX_CONTEXTUAL_REASONING_CHARS]
    changes["dependency_metadata"] = metadata
    return None


def _fit_revision_to_class(
    report_state: ReportRepository,
    report_id: str,
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    """Keep a revision inside the class of the finding it names.

    A finding keeps its class and the metadata that belongs to it. Writing an
    exploit onto a dependency record would leave it carrying a package pin next
    to a request against an endpoint, so the proof belongs in its own dynamic
    finding instead. A dependency finding is still re-rated, through the
    contextual CVSS it was filed with.
    """
    matched = next(
        (r for r in report_state.get_existing_vulnerabilities() if r.get("id") == report_id),
        None,
    )
    if matched is None:
        return None

    matched_class = _finding_class_of(matched)
    foreign = (
        _DEPENDENCY_ONLY_UPDATE_FIELDS
        if matched_class == "dynamic"
        else _DYNAMIC_ONLY_UPDATE_FIELDS
    )
    offending = [name for name in foreign if name in changes]
    if offending:
        return _reject_cross_class_revision(report_id, matched_class, offending)
    if matched_class == "dynamic":
        return None
    return _rate_dependency_revision(report_id, matched, changes)


def _read_revision(
    report_id: str, update_reason: str, fields: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return the changes a revision asks for, or the reason it cannot be acted on."""
    if not report_id or not str(update_reason or "").strip():
        missing = "report_id" if not report_id else "update_reason"
        return {}, {
            "success": False,
            "error": (
                f"{missing} cannot be empty - name the report you are revising and state "
                "what you learned that it does not yet carry"
            ),
        }

    changes, errors = _collect_update_changes(fields)
    if errors:
        return {}, {"success": False, "error": "Validation failed", "errors": errors}
    if not changes:
        return {}, {
            "success": False,
            "error": "No fields to update - pass at least one field you want to replace",
        }
    return changes, None


def _do_update(
    *,
    report_id: str,
    update_reason: str,
    fields: dict[str, Any],
    agent_id: str | None = None,
    agent_name: str | None = None,
    report_state: ReportRepository | None = None,
) -> dict[str, Any]:
    """Apply an agent's own revision to a report it can name.

    Editing a finding is its own operation and the only way a filed finding
    changes. Deduplication never reaches this path: it only decides whether a
    new candidate is a finding already on file.
    """
    report_id = (report_id or "").strip()
    changes, rejection = _read_revision(report_id, update_reason, fields)
    if rejection is not None:
        return rejection

    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
        }

    class_error = _fit_revision_to_class(report_state, report_id, changes)
    if class_error is not None:
        return class_error

    mutation = FindingService(report_state, check_duplicate).revise(
        ReviseFinding(
            report_id=report_id,
            changes=changes,
            reason=update_reason,
            agent_id=agent_id,
            agent_name=agent_name,
        )
    )
    if mutation.status == "failed":
        return {
            "success": False,
            "error": (
                f"Failed to revise report '{report_id}': {mutation.error}. "
                "The report still carries its previous content; retry the update."
            ),
            "report_id": report_id,
        }
    if mutation.status != "updated" or mutation.finding is None:
        error = (
            f"Report with id '{report_id}' not found"
            if mutation.status == "missing"
            else f"Report '{report_id}' already says this - nothing in your update changes it"
        )
        return {"success": False, "error": error, "report_id": report_id}
    updated = mutation.finding

    logger.info(
        "Vulnerability report %s revised by its author: severity=%s cvss=%s fields=%s",
        report_id,
        updated.get("severity"),
        updated.get("cvss"),
        ", ".join(sorted(changes)),
    )
    return {
        "success": True,
        "action": "updated",
        "message": f"Report '{report_id}' now carries your revision. Do not file it again.",
        "report_id": report_id,
        "updated_fields": sorted(changes),
        "severity": updated.get("severity"),
        "cvss_score": updated.get("cvss"),
    }
