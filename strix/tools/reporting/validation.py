"""Validation and normalization for finding commands."""

from __future__ import annotations

import logging
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from strix.tools.proxy.tools import existing_request_ids


if TYPE_CHECKING:
    from agents import RunContextWrapper


logger = logging.getLogger(__name__)


_MAX_CONTEXTUAL_REASONING_CHARS = 2000


_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


_CODE_LOCATION_FIELDS = (
    "file",
    "start_line",
    "end_line",
    "snippet",
    "label",
    "fix_before",
    "fix_after",
)


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _normalize_code_locations(
    raw: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    cleaned: list[dict[str, Any]] = []
    for loc in raw:
        normalized: dict[str, Any] = {}
        for field in _CODE_LOCATION_FIELDS:
            if field not in loc or loc[field] is None:
                continue
            value = loc[field]
            if field in ("start_line", "end_line"):
                try:
                    normalized[field] = int(value)
                except (TypeError, ValueError):
                    continue
            else:
                text = (
                    str(value).strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else str(value).strip()
                )
                if text:
                    normalized[field] = text
        if normalized.get("file") and normalized.get("start_line") is not None:
            cleaned.append(normalized)
    return cleaned or None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def _calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    # CVSS is an optional path for reporting tools; avoid startup work when unused.
    from cvss import CVSS3  # noqa: PLC0415

    vector = (
        f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
        f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
        f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
        f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
    )

    try:
        cvss = CVSS3(vector)
        score = cvss.scores()[0]
        base_severity = cvss.severities()[0].lower()
    except Exception as exc:
        msg = f"Failed to calculate CVSS for validated vector: {vector}"
        raise ValueError(msg) from exc

    severity = "info" if base_severity == "none" else base_severity
    return score, severity, vector


_REQUIRED_FIELDS = {
    "title": "Title cannot be empty",
    "description": "Description cannot be empty",
    "impact": "Impact cannot be empty",
    "target": "Target cannot be empty",
    "technical_analysis": "Technical analysis cannot be empty",
    "poc_description": "PoC description cannot be empty",
    "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    "remediation_steps": "Remediation steps cannot be empty",
    "evidence": "Evidence cannot be empty - provide concrete proof of the finding",
    "assumptions": "Assumptions cannot be empty - state exploitability prerequisites",
}

_VALID_FIX_EFFORT = frozenset({"trivial", "low", "medium", "high"})
_VALID_CONFIDENCE = frozenset({"high", "medium", "low"})
_MAX_HTTP_EXCHANGE_IDS = 10
_MAX_HTTP_EXCHANGE_ID_CHARS = 128


def _validate_required_text(fields: dict[str, str]) -> list[str]:
    """Report every ``_REQUIRED_FIELDS`` entry that arrived blank."""
    return [
        msg for name, msg in _REQUIRED_FIELDS.items() if not str(fields.get(name) or "").strip()
    ]


def _normalize_http_exchange_ids(raw: Any) -> tuple[list[str] | None, list[str]]:
    """Return distinct proxy exchange ids in their original order."""
    if raw is None:
        return None, []
    if not isinstance(raw, list):
        return None, ["http_exchange_ids must be a list of proxy request ids"]

    normalized: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(raw):
        if not isinstance(value, str):
            errors.append(f"http_exchange_ids[{index}] must be a string")
            continue
        request_id = value.strip()
        if not request_id:
            errors.append(f"http_exchange_ids[{index}] cannot be empty")
            continue
        if len(request_id) > _MAX_HTTP_EXCHANGE_ID_CHARS:
            errors.append(
                f"http_exchange_ids[{index}] must be {_MAX_HTTP_EXCHANGE_ID_CHARS} "
                "characters or fewer"
            )
            continue
        if any(ord(char) < 0x21 or ord(char) > 0x7E for char in request_id):
            errors.append(f"http_exchange_ids[{index}] must contain only visible ASCII characters")
            continue
        if not request_id.isdigit():
            errors.append(f"http_exchange_ids[{index}] must be a numeric proxy request id")
            continue
        if request_id not in seen:
            seen.add(request_id)
            normalized.append(request_id)
            if len(normalized) > _MAX_HTTP_EXCHANGE_IDS:
                errors.append(
                    f"http_exchange_ids can contain at most "
                    f"{_MAX_HTTP_EXCHANGE_IDS} distinct request ids"
                )
                break
    return normalized, errors


_HTTP_EXCHANGE_DROPPED_WARNING = (
    "http_exchange_ids were not stored: the proxy project could not be reached to verify "
    "them. Attach them with update_vulnerability_report when the proxy responds again."
)


async def _verify_http_exchange_ids(
    ctx: RunContextWrapper,
    raw: Any,
) -> tuple[list[str] | None, list[str], str | None]:
    """Verify proxy exchange IDs against the current Caido project.

    IDs the project does not know are rejected. When the proxy itself cannot be
    queried the IDs are dropped and a warning is returned instead, so a proxy
    outage never blocks a finding and unverified IDs are never recorded as
    evidence.
    """
    request_ids, errors = _normalize_http_exchange_ids(raw)
    if request_ids is None or errors or not request_ids:
        return request_ids, errors, None

    try:
        existing_ids = await existing_request_ids(ctx, request_ids)
    except Exception:  # noqa: BLE001
        logger.warning(
            "Could not verify HTTP exchange IDs against the current Caido project",
            exc_info=True,
        )
        return None, [], _HTTP_EXCHANGE_DROPPED_WARNING

    missing_ids = [request_id for request_id in request_ids if request_id not in existing_ids]
    if missing_ids:
        return (
            None,
            [
                "http_exchange_ids do not exist in the current proxy project: "
                + ", ".join(missing_ids)
            ],
            None,
        )
    return request_ids, [], None


def _with_warning(result: dict[str, Any], warning: str | None) -> dict[str, Any]:
    if warning and result.get("success"):
        result["warning"] = warning
    return result


def _validate_cvss_breakdown(breakdown: Any) -> list[str]:
    """Check the 8 CVSS metrics are all present with legal values."""
    if not isinstance(breakdown, dict) or not breakdown:
        return ["cvss_breakdown: must be an object with the 8 CVSS metrics"]
    return [
        f"Invalid {name}: {breakdown.get(name)}. Must be one of: {valid}"
        for name, valid in _CVSS_VALID.items()
        if breakdown.get(name) not in valid
    ]


def _validate_identifiers(
    cve: str | None, cwe: str | None
) -> tuple[str | None, str | None, list[str]]:
    """Normalize and validate the optional CVE / CWE identifiers."""
    errors: list[str] = []
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)
    return cve, cwe, errors


def _validate_analysis_fields(
    *,
    counterevidence: str,
    confidence: str,
    confidence_rationale: str | None,
    severity_change_conditions: str,
) -> list[str]:
    """Validate the counterevidence / confidence closure metadata."""
    errors: list[str] = []
    if not str(counterevidence or "").strip():
        errors.append(
            "Counterevidence cannot be empty - state the strongest evidence against "
            "this finding, or what you checked and found none (e.g. 'no input "
            "validation, WAF, or authorization check found on this path')"
        )
    if not str(severity_change_conditions or "").strip():
        errors.append(
            "severity_change_conditions cannot be empty - state the one concrete piece "
            "of evidence that would raise or lower the severity"
        )
    if confidence not in _VALID_CONFIDENCE:
        errors.append(
            f"Invalid confidence: {confidence!r}. Must be one of: {sorted(_VALID_CONFIDENCE)}"
        )
    elif confidence != "high" and not str(confidence_rationale or "").strip():
        errors.append(
            "confidence_rationale is required when confidence is not 'high' - name the "
            "gap (e.g. static-only trace, unconfirmed reachability, no runtime access)"
        )
    return errors


def _validate_fix_verification(
    locations: list[dict[str, Any]] | None,
    fix_verification: str | None,
) -> list[str]:
    """Require a verification statement whenever an applyable fix is proposed."""
    if not locations or not any(loc.get("fix_after") for loc in locations):
        return []
    if str(fix_verification or "").strip():
        return []
    return [
        "fix_verification is REQUIRED when any code_location carries a 'fix_after' - "
        "a suggestion a reviewer can click to apply must be verified first. State, in "
        "order: (1) security closure - re-trace the source->sink path through the "
        "PATCHED code and say why it is now blocked; (2) bypass review - re-read the "
        "diff without your original rationale and name the equivalent sinks, sibling "
        "call sites, and alternate malicious input classes you checked; (3) preserved "
        "behavior - the legitimate inputs, APIs, and error semantics that still work; "
        "(4) how each was checked (executed vs. reasoned), naming any unrun check as "
        "an explicit gap. If you cannot make these statements, drop 'fix_after' and "
        "leave the location informational."
    ]
