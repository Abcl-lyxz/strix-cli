"""Dependency finding tool adapter and SCA-specific normalization."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from strix.application.findings import FindingService
from strix.domain.findings import CreateFinding
from strix.report.dedupe import check_duplicate
from strix.tools.reporting.context import caller_identity as _caller_identity
from strix.tools.reporting.context import report_repository as _report_state_from_context
from strix.tools.reporting.validation import (
    _CVSS_VALID,
    _MAX_CONTEXTUAL_REASONING_CHARS,
    _VALID_FIX_EFFORT,
    _calculate_cvss,
    _extract_cve,
    _extract_cwe,
    _validate_cve,
    _validate_cwe,
)


if TYPE_CHECKING:
    from strix.ports.reporting import ReportRepository


logger = logging.getLogger(__name__)


_DEP_SEVERITY_FROM_CVSS = {
    (9.0, 10.0): "critical",
    (7.0, 9.0): "high",
    (4.0, 7.0): "medium",
    (0.0, 4.0): "low",
}


def _dependency_severity(advisory_cvss: float | None) -> tuple[float, str]:
    if advisory_cvss is None:
        return 0.0, "info"
    score = max(0.0, min(10.0, advisory_cvss))
    for (lo, hi), label in _DEP_SEVERITY_FROM_CVSS.items():
        if lo <= score < hi or (hi == 10.0 and score == 10.0):
            return score, label
    return score, "none"


_VALID_REACHABILITY = frozenset(
    {
        "not_imported",
        "imported",
        "vulnerable_symbol_used",
        "reachable_call_path",
        "unknown",
    }
)


def _validate_manifest_path(manifest_path: str | None) -> str | None:
    """Return an error message when manifest_path is missing or unsafe."""
    path = (manifest_path or "").strip()
    if not path:
        return (
            "manifest_path is required: pass the repo-relative path of the "
            "lockfile/manifest where the vulnerable version was observed "
            "(trivy's Target, e.g. 'package-lock.json' or "
            "'services/api/pom.xml'). It binds the finding to its exact file "
            "so remediation can target the right repository."
        )
    if path.startswith("/") or "\\" in path or path.split("/")[0].endswith(":"):
        return f"manifest_path must be a relative path within the repository, got {path!r}"
    segments = path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return f"manifest_path must not contain empty, '.', or '..' segments, got {path!r}"
    return None


def _validate_contextual_cvss(
    breakdown: dict[str, str] | None,
    reasoning: str | None,
) -> list[str]:
    errors: list[str] = []
    if not breakdown:
        errors.append(
            "contextual_cvss_breakdown is required: rate the CVE in this codebase with "
            "all 8 CVSS v3.1 metrics (attack_vector, attack_complexity, "
            "privileges_required, user_interaction, scope, confidentiality, integrity, "
            "availability). When your trace does not change the published rating, repeat "
            "the advisory's own metrics and adjust only what the usage level proves - a "
            "package the code never imports is normally N on all three impact metrics."
        )
    else:
        for name, valid in _CVSS_VALID.items():
            value = breakdown.get(name)
            if value not in valid:
                errors.append(
                    f"Invalid contextual_cvss_breakdown {name}: {value}. Must be one of: {valid}"
                )
    if not (reasoning or "").strip():
        errors.append(
            "contextual_cvss_reasoning is required: state what you observed in this "
            "codebase that justifies the contextual rating. A contextual score with "
            "no reasoning is not shown."
        )
    return errors


def _validate_advisory_cvss(advisory_cvss: float | None) -> str | None:
    if advisory_cvss is None:
        return (
            "advisory_cvss is required: read the published advisory base score "
            "(0.0-10.0) off the advisory (trivy CVSS / NVD / GHSA). It is the "
            "published reference the finding is rated against — do not omit it "
            "or the finding cannot be rated."
        )
    if not 0.0 <= advisory_cvss <= 10.0:
        return f"advisory_cvss must be between 0.0 and 10.0, got {advisory_cvss}"
    return None


def _resolve_dependency_rating(
    advisory_cvss: float | None,
    contextual_cvss_breakdown: dict[str, str] | None,
) -> tuple[float | None, str, float | None, str | None]:
    """Rate the finding.

    A contextual breakdown works exactly like a normal finding's
    ``cvss_breakdown``: the agent supplies the 8 metrics as observed in this
    codebase and the score/vector are computed from them. When provided it
    rates the finding; the advisory score stays as the published reference.
    """
    if contextual_cvss_breakdown:
        score, severity, vector = _calculate_cvss(contextual_cvss_breakdown)
        return score, severity, score, vector
    score, severity = _dependency_severity(advisory_cvss)
    return score, severity, None, None


def _build_dependency_metadata(
    *,
    package_name: str,
    installed_version: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
    introduced_by: str | None,
    dependency_path: str | None,
    manifest_path: str | None = None,
    reachability: str | None = None,
    reachability_evidence: str | None = None,
    advisory_cvss: float | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_score: float | None = None,
    contextual_cvss_vector: str | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "package_name": package_name.strip(),
        "installed_version": installed_version.strip(),
    }
    if advisory_cvss is not None:
        metadata["advisory_cvss"] = advisory_cvss
    if package_ecosystem and package_ecosystem.strip():
        metadata["package_ecosystem"] = package_ecosystem.strip()
    if manifest_path and manifest_path.strip():
        metadata["manifest_path"] = manifest_path.strip()
    if fixed_version and fixed_version.strip():
        metadata["fixed_version"] = fixed_version.strip()
    if introduced_by and introduced_by.strip():
        metadata["introduced_by"] = introduced_by.strip()
    if dependency_path and dependency_path.strip():
        metadata["dependency_path"] = dependency_path.strip()
    if reachability and reachability.strip():
        metadata["reachability"] = reachability.strip()
        if reachability_evidence and reachability_evidence.strip():
            metadata["reachability_evidence"] = reachability_evidence.strip()
    # Contextual CVSS is only meaningful as the full breakdown, its computed
    # score/vector, and the reasoning a reader can check — an incomplete set
    # is dropped.
    reasoning = str(contextual_cvss_reasoning or "").strip()
    if (
        contextual_cvss_breakdown
        and contextual_cvss_score is not None
        and contextual_cvss_vector
        and reasoning
    ):
        metadata["contextual_cvss_breakdown"] = contextual_cvss_breakdown
        metadata["contextual_cvss_score"] = contextual_cvss_score
        metadata["contextual_cvss_vector"] = contextual_cvss_vector
        metadata["contextual_cvss_reasoning"] = reasoning[:_MAX_CONTEXTUAL_REASONING_CHARS]
    return metadata


_REACHABILITY_EVIDENCE_LABELS = {
    "not_imported": "not imported by application code",
    "imported": "imported by application code; affected API usage unconfirmed",
    "vulnerable_symbol_used": "the advisory's affected API is used in application code",
    "reachable_call_path": (
        "a call path from application code to the vulnerable function was proven"
    ),
}


def _build_dependency_evidence(
    *,
    cve: str,
    package_name: str,
    installed_version: str,
    fixed_version: str | None,
    introduced_by: str | None,
    dependency_path: str | None,
    reachability: str | None = None,
    reachability_evidence: str | None = None,
) -> str:
    evidence = (
        f"**Advisory evidence:** `{cve}` applies to `{package_name}` "
        f"at installed version `{installed_version}`."
    )
    if fixed_version and fixed_version.strip():
        evidence += f" The advisory is fixed in `{fixed_version.strip()}`."
    if introduced_by and introduced_by.strip():
        evidence += (
            f"\n\n**Transitive dependency:** introduced by the direct "
            f"dependency `{introduced_by.strip()}`."
        )
    if dependency_path and dependency_path.strip():
        evidence += f"\n\n**Dependency chain:** `{dependency_path.strip()}`"
    label = _REACHABILITY_EVIDENCE_LABELS.get((reachability or "").strip().lower())
    if label:
        evidence += f"\n\n**Usage analysis:** {label}."
        if reachability_evidence and reachability_evidence.strip():
            evidence += f" {reachability_evidence.strip()}"
        evidence += (
            " This is a prioritization signal from static analysis, not a"
            " proof of exploitability or of safety."
        )
    return evidence


async def _do_create_dependency(  # noqa: PLR0912
    *,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
    cwe: str | None,
    advisory_cvss: float | None,
    technical_analysis: str | None,
    fix_effort: str,
    introduced_by: str | None = None,
    dependency_path: str | None = None,
    manifest_path: str | None = None,
    reachability: str = "unknown",
    reachability_evidence: str | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_reasoning: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    report_state: ReportRepository | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    required = {
        "title": title,
        "description": description,
        "target": target,
        "package_name": package_name,
        "installed_version": installed_version,
        "package_ecosystem": package_ecosystem,
        "impact": impact,
        "remediation_steps": remediation_steps,
        "assumptions": assumptions,
    }
    for name, value in required.items():
        if not str(value or "").strip():
            errors.append(f"{name} cannot be empty")

    parsed_cve = _extract_cve(cve or "")
    cve_err = _validate_cve(parsed_cve)
    if cve_err:
        errors.append(cve_err)

    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    manifest_err = _validate_manifest_path(manifest_path)
    if manifest_err:
        errors.append(manifest_err)

    reachability = (reachability or "unknown").strip().lower()
    if reachability not in _VALID_REACHABILITY:
        errors.append(
            f"Invalid reachability: {reachability!r}. Must be one of: {sorted(_VALID_REACHABILITY)}"
        )
    elif not (reachability_evidence or "").strip():
        errors.append(
            "reachability_evidence is required: cite the concrete proof (import "
            "file:line, matched symbol usage, or govulncheck call path), or, for "
            "'unknown', say what you searched and why the result is inconclusive. "
            "Never claim a reachability level without evidence."
        )

    errors.extend(_validate_contextual_cvss(contextual_cvss_breakdown, contextual_cvss_reasoning))

    advisory_err = _validate_advisory_cvss(advisory_cvss)
    if advisory_err:
        errors.append(advisory_err)

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        cvss_score, severity, contextual_score, contextual_vector = _resolve_dependency_rating(
            advisory_cvss, contextual_cvss_breakdown
        )
    except ValueError as exc:
        return {"success": False, "error": "Validation failed", "errors": [str(exc)]}
    dependency_metadata = _build_dependency_metadata(
        package_name=package_name,
        installed_version=installed_version,
        package_ecosystem=package_ecosystem,
        fixed_version=fixed_version,
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        manifest_path=manifest_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
        advisory_cvss=advisory_cvss,
        contextual_cvss_breakdown=contextual_cvss_breakdown,
        contextual_cvss_score=contextual_score,
        contextual_cvss_vector=contextual_vector,
        contextual_cvss_reasoning=contextual_cvss_reasoning,
    )
    evidence = _build_dependency_evidence(
        cve=parsed_cve,
        package_name=package_name.strip(),
        installed_version=installed_version.strip(),
        fixed_version=fixed_version,
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
    )

    if report_state is None:
        logger.warning("No scan report state; dependency report not persisted")
        return {
            "success": True,
            "message": f"Dependency finding '{title}' created (not persisted)",
            "warning": "Report could not be persisted - report state unavailable",
        }

    candidate = {
        "title": title,
        "description": description,
        "target": target,
        "cve": parsed_cve,
        "dependency_metadata": dependency_metadata,
        "technical_analysis": technical_analysis,
    }
    fields = {
        "title": title,
        "description": description,
        "severity": severity,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "remediation_steps": remediation_steps,
        "evidence": evidence,
        "assumptions": assumptions,
        "fix_effort": fix_effort,
        "cvss": cvss_score if advisory_cvss is not None else None,
        "cve": parsed_cve,
        "cwe": cwe,
        "dependency_metadata": dependency_metadata,
    }
    mutation = await FindingService(report_state, check_duplicate).create(
        CreateFinding(
            title=title,
            finding_class="dependency_cve",
            candidate=candidate,
            fields=fields,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )
    )
    if mutation.status == "duplicate":
        duplicate_id = mutation.duplicate_id or ""
        return {
            "success": False,
            "error": (
                f"Potential duplicate (id={duplicate_id[:8]}...) — "
                "do not re-report the same dependency finding"
            ),
            "duplicate_of": duplicate_id,
            "confidence": mutation.confidence,
            "reason": mutation.reason,
        }
    if mutation.status != "created" or mutation.report_id is None:
        return {
            "success": False,
            "error": (
                f"Failed to create dependency report: {mutation.error}. "
                "The finding was not stored; file it again."
            ),
        }
    logger.info(
        "Dependency report created: id=%s cve=%s package=%s severity=%s",
        mutation.report_id,
        parsed_cve,
        package_name,
        severity,
    )
    return {
        "success": True,
        "message": f"Dependency finding '{title}' created successfully",
        "report_id": mutation.report_id,
        "severity": severity,
        "cve": parsed_cve,
    }


@function_tool(timeout=180, strict_mode=False)
async def create_dependency_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    advisory_cvss: float,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str,
    manifest_path: str | None = None,
    fixed_version: str | None = None,
    cwe: str | None = None,
    technical_analysis: str | None = None,
    fix_effort: str = "low",
    introduced_by: str | None = None,
    dependency_path: str | None = None,
    reachability: str = "unknown",
    reachability_evidence: str | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> str:
    """File a known-CVE dependency (SCA) finding — one report per CVE x package.

    Use this instead of ``create_vulnerability_report`` when the finding
    is a **known-CVE supply-chain issue**: a vulnerable third-party
    package/version identified from a lockfile, manifest, or SBOM. Unlike
    a dynamic finding, you do NOT need to trigger the vulnerability with a
    live PoC — a verified advisory + the affected installed version is the
    evidence.

    **When to file**:

    - A dependency is pinned to a version covered by a published CVE.
    - You have verified the CVE ID and the installed version falls in the
      affected range (use ``web_search`` if unsure).

    **When NOT to file**:

    - Dynamically-proven vulnerabilities → use
      ``create_vulnerability_report`` (``finding_class`` dynamic).
    - Outdated-but-not-vulnerable dependencies with no CVE.
    - Re-reporting the same CVE/package already filed.

    **Reachability**: do NOT silently downgrade or suppress a finding
    because the vulnerable code path may be unreachable — report it, and
    record what the usage analysis showed via the structured
    ``reachability`` + ``reachability_evidence`` fields (see the
    dependency-cve-scanning skill for the analysis procedure). The level
    is an evidence ladder, never an exploitability verdict:

    - ``not_imported`` — the package is never imported/required by
      application code (strongest de-prioritization signal; still not
      proof of safety — dynamic loading, reflection, or framework wiring
      can evade static search).
    - ``imported`` — application code imports the package, but usage of
      the advisory's affected API was not confirmed.
    - ``vulnerable_symbol_used`` — the advisory's affected
      function/class/API appears in application code.
    - ``reachable_call_path`` — a call-graph tool (e.g. ``govulncheck``)
      proved a path from application code to the vulnerable function.
    - ``unknown`` — usage analysis was not performed or was inconclusive.

    Severity comes from ``contextual_cvss_breakdown`` when you provide one
    (computed exactly like a normal finding's ``cvss_breakdown``), otherwise
    from ``advisory_cvss``. The reachability level alone never changes the
    rating, only prioritization.

    **Formatting**: use markdown in text fields (``**bold**``, ``inline
    code`` for package/version identifiers, fenced code blocks for
    manifest excerpts). No internal paths/tooling/agent references.

    Args:
        title: e.g. ``"CVE-2024-1234 in lodash 4.17.20 (prototype pollution)"``.
        description: What the CVE is and why the pinned version is affected.
        target: Affected repository / project / manifest.
        cve: ``CVE-YYYY-NNNNN`` — required and must be verified.
        package_name: Affected package name (e.g. ``lodash``).
        installed_version: The version currently pinned/installed.
        impact: What the CVE enables; business risk in this context.
        remediation_steps: How to fix (usually upgrade to a fixed version).
        assumptions: Exploitability/reachability assumptions & confidence.
        package_ecosystem: e.g. ``npm`` / ``pypi`` / ``maven`` / ``go``.
        fixed_version: First non-vulnerable version, if known.
        cwe: ``CWE-NNN`` (most specific) if certain, else omit.
        advisory_cvss: **Required.** Published advisory base score
            (0.0-10.0) — read it off the advisory (trivy CVSS / NVD / GHSA).
            It is the published reference the finding is rated against and
            rates the finding whenever you give no contextual breakdown, so
            it must be the real published value; do not guess or omit it.
        technical_analysis: Optional deeper mechanism/root-cause detail.
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``
            (dependency upgrades are usually ``trivial``/``low``).
        introduced_by: For a **transitive** dependency, the direct
            dependency (from the project's own manifest) that pulls the
            vulnerable package in, as ``name@version`` (e.g.
            ``express@4.18.1``). Omit when the vulnerable package is
            itself a direct dependency.
        dependency_path: The resolution chain from the direct dependency
            to the vulnerable package, joined with `` > `` (e.g.
            ``express@4.18.1 > body-parser@1.20.0 > qs@6.10.2``). Omit
            for direct dependencies.
        manifest_path: **Required.** The repo-relative path of the
            lockfile/manifest where the vulnerable version was observed —
            trivy's ``Target`` (e.g. ``package-lock.json``,
            ``services/api/pom.xml``). Strip any scan-workspace or repo
            checkout directory prefix so the path is relative to the
            repository root. This binds the finding to its exact file so
            remediation can target the right repository.
        reachability: Usage-evidence level from static analysis — one of
            ``not_imported`` / ``imported`` / ``vulnerable_symbol_used`` /
            ``reachable_call_path`` / ``unknown``. Claim only what the
            evidence proves; when in doubt use ``unknown``.
        reachability_evidence: **Required.** The concrete proof for the
            claimed level, or, for ``unknown``, what you searched and why
            the result is inconclusive: repo-relative
            ``file:line`` of the import or symbol usage, the matched
            advisory symbols, or the govulncheck call-path excerpt.
            Whenever you found the vulnerable symbol in use, also give the
            **source-to-sink trace** here: start at the vulnerable package
            call site and walk backwards hop by hop to the entry point
            that carries untrusted input (HTTP route, CLI argument, queue
            message, webhook, config file), going one step deeper whenever
            a hop is a wrapper. Write it as ``entry point -> intermediate
            call -> package call`` with a ``file:line`` per hop, name what
            each hop enforces (auth, role check, validation, a flag that
            is off in production), and say who controls the input. State
            it plainly when no entry point reaches the sink — that is the
            most useful result a reader can get.
        contextual_cvss_breakdown: **Required.** Full CVSS v3.1 rating of this
            CVE **in this codebase** — the same 8-metric object as
            ``create_vulnerability_report``'s ``cvss_breakdown``:
            ``attack_vector`` (N/A/L/P), ``attack_complexity`` (L/H),
            ``privileges_required`` (N/L/H), ``user_interaction`` (N/R),
            ``scope`` (U/C), ``confidentiality`` / ``integrity`` /
            ``availability`` (N/L/H). All 8 metrics are required when the
            field is set, and the contextual score/vector are computed
            from them — you never supply a score. Start from the
            advisory's published metrics and change only what the
            **source-to-sink trace** you recorded in
            ``reachability_evidence`` proves is different here: derive
            ``attack_vector`` / ``privileges_required`` /
            ``user_interaction`` from what the entry point actually
            requires, ``attack_complexity`` from the preconditions the
            hops enforce, and the impact metrics from the data and
            privileges reachable at the sink. When provided, this rating
            determines the finding's severity; ``advisory_cvss`` stays as
            the published reference. Send it on every report: when the
            trace does not change the published rating, or when you could
            not complete the trace, repeat the advisory's own metrics and
            adjust only what the usage level itself proves (a package the
            code never imports is normally ``N`` on all three impact
            metrics), then say so in the reasoning.
        contextual_cvss_reasoning: **Required.** Two to four detailed
            sentences that a reviewer can verify without opening the repo:
            how the application uses the package, which call sites or
            configuration you inspected (repo-relative ``file:line``),
            which input reaches the vulnerable code and whether an
            attacker controls it, and what the adjustment therefore
            changes. State the source-to-sink chain explicitly, hop by
            hop, as ``entry point -> intermediate call -> package call``
            with a ``file:line`` for each hop. Cite concrete evidence,
            never a generic statement such as "low risk". The user reads
            this text next to the adjusted score, so an adjustment
            without it is discarded.
    """
    agent_id, agent_name = _caller_identity(ctx)

    result = await _do_create_dependency(
        title=title,
        description=description,
        target=target,
        cve=cve,
        package_name=package_name,
        installed_version=installed_version,
        impact=impact,
        remediation_steps=remediation_steps,
        assumptions=assumptions,
        package_ecosystem=package_ecosystem,
        fixed_version=fixed_version,
        cwe=cwe,
        advisory_cvss=advisory_cvss,
        technical_analysis=technical_analysis,
        fix_effort=fix_effort,
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        manifest_path=manifest_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
        contextual_cvss_breakdown=contextual_cvss_breakdown,
        contextual_cvss_reasoning=contextual_cvss_reasoning,
        agent_id=agent_id,
        agent_name=agent_name,
        report_state=_report_state_from_context(ctx),
    )
    return json.dumps(result, ensure_ascii=False, default=str)
