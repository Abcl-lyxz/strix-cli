"""Reporting tools — file vuln findings (with dedup + CVSS) and read them back.

``create_vulnerability_report`` / ``create_dependency_report`` file findings;
``list_reports`` / ``get_report`` let any agent (notably the root orchestrator)
review what's been filed so far across the whole scan.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from strix.application.findings import FindingService
from strix.domain.findings import CreateFinding
from strix.report.dedupe import check_duplicate
from strix.tools.reporting.context import (
    caller_identity as _caller_identity,
)
from strix.tools.reporting.context import (
    report_repository as _report_state_from_context,
)
from strix.tools.reporting.revisions import _do_update
from strix.tools.reporting.validation import (
    _VALID_FIX_EFFORT,
    _calculate_cvss,
    _normalize_code_locations,
    _normalize_http_exchange_ids,
    _validate_analysis_fields,
    _validate_code_locations,
    _validate_cvss_breakdown,
    _validate_fix_verification,
    _validate_identifiers,
    _validate_required_text,
    _verify_http_exchange_ids,
    _with_warning,
)


if TYPE_CHECKING:
    from strix.ports.reporting import ReportRepository


logger = logging.getLogger(__name__)


async def _do_create(
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    counterevidence: str,
    confidence: str,
    severity_change_conditions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None,
    method: str | None,
    cve: str | None,
    cwe: str | None,
    code_locations: list[dict[str, Any]] | None,
    http_exchange_ids: list[str] | None = None,
    confidence_rationale: str | None = None,
    fix_verification: str | None = None,
    fix_pr_body: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    report_state: ReportRepository | None = None,
) -> dict[str, Any]:
    errors: list[str] = _validate_required_text(
        {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "remediation_steps": remediation_steps,
            "evidence": evidence,
            "assumptions": assumptions,
        }
    )

    confidence = (confidence or "").strip().lower()
    errors.extend(
        _validate_analysis_fields(
            counterevidence=counterevidence,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            severity_change_conditions=severity_change_conditions,
        )
    )

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    errors.extend(_validate_cvss_breakdown(cvss_breakdown))

    parsed_locations = _normalize_code_locations(code_locations)
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    errors.extend(_validate_fix_verification(parsed_locations, fix_verification))
    cve, cwe, identifier_errors = _validate_identifiers(cve, cwe)
    errors.extend(identifier_errors)
    normalized_http_exchange_ids, http_exchange_errors = _normalize_http_exchange_ids(
        http_exchange_ids
    )
    errors.extend(http_exchange_errors)

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        cvss_score, severity, _vector = _calculate_cvss(cvss_breakdown)
    except ValueError as exc:
        return {"success": False, "error": "Validation failed", "errors": [str(exc)]}

    if report_state is None:
        logger.warning("No scan report state; vulnerability report not persisted")
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created (not persisted)",
            "warning": "Report could not be persisted - report state unavailable",
        }

    candidate = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "endpoint": endpoint,
        "method": method,
    }
    report_fields: dict[str, Any] = {
        "title": title,
        "description": description,
        "severity": severity,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "evidence": evidence,
        "assumptions": assumptions,
        "counterevidence": counterevidence,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "severity_change_conditions": severity_change_conditions,
        "fix_effort": fix_effort,
        "cvss": cvss_score,
        "cvss_breakdown": cvss_breakdown,
        "endpoint": endpoint,
        "method": method,
        "cve": cve,
        "cwe": cwe,
        "code_locations": parsed_locations,
        "fix_verification": fix_verification,
        "fix_pr_body": fix_pr_body,
        "http_exchange_ids": normalized_http_exchange_ids,
    }

    mutation = await FindingService(report_state, check_duplicate).create(
        CreateFinding(
            title=title,
            finding_class="dynamic",
            candidate=candidate,
            fields=report_fields,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )
    )
    if mutation.status == "duplicate":
        duplicate_id = mutation.duplicate_id or ""
        return {
            "success": False,
            "error": (
                f"Potential duplicate of '{mutation.duplicate_title}' "
                f"(id={duplicate_id[:8]}...) — do not re-report the same vulnerability"
            ),
            "duplicate_of": duplicate_id,
            "duplicate_title": mutation.duplicate_title,
            "confidence": mutation.confidence,
            "reason": mutation.reason,
        }
    if mutation.status != "created" or mutation.report_id is None:
        return {
            "success": False,
            "error": (
                f"Failed to create vulnerability report: {mutation.error}. "
                "The finding was not stored; file it again."
            ),
        }
    logger.info(
        "Vulnerability report created: id=%s severity=%s cvss=%.1f title=%s",
        mutation.report_id,
        severity,
        cvss_score,
        title,
    )
    return {
        "success": True,
        "message": f"Vulnerability report '{title}' created successfully",
        "report_id": mutation.report_id,
        "severity": severity,
        "cvss_score": cvss_score,
    }


@function_tool(timeout=180, strict_mode=False)
async def create_vulnerability_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    counterevidence: str,
    confidence: str,
    severity_change_conditions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    http_exchange_ids: list[str] | None = None,
    confidence_rationale: str | None = None,
    fix_verification: str | None = None,
    fix_pr_body: str | None = None,
) -> str:
    """File a vulnerability report — one report per fully-verified finding.

    **When to file**: you have a concrete vulnerability with a working
    proof-of-concept and you're 100% sure it's a real issue.

    **When NOT to file**:

    - General security observations without a specific vulnerability.
    - Suspicions you haven't confirmed with a PoC.
    - Tracking multiple vulnerabilities at once — one report per vuln.
    - Re-reporting something you (or another agent) already filed.
    - Known-CVE dependency / supply-chain findings that can't be
      dynamically PoC'd — a vulnerable dependency version pinned in a
      lockfile/manifest that matches a published advisory. File those
      with ``create_dependency_report`` instead, never with this tool.

    **Reporting and severity gate**:

    - A reachable endpoint, unusual response, weak configuration, or
      reconnaissance artifact is not by itself a vulnerability. File a
      report only when the PoC demonstrates an unauthorized security
      consequence or a realistic, fully validated path to one.
    - Score only the reasonable final impact supported by the PoC. Do
      not score speculative pivots or consequences that require another
      unverified vulnerability.
    - Network reachability and missing authentication affect
      exploitability; neither creates Confidentiality, Integrity, or
      Availability impact by itself.
    - Public metadata, internal-looking names or addresses, software
      versions, intended client-side code, and source maps without
      secrets or restricted source normally have ``C:N``.
    - Configuration and transport observations require a realistic
      attacker-controlled exploit and direct security impact. Client
      errors, compatibility issues, fingerprinting, and attack-surface
      discovery alone should not be filed as vulnerabilities.
    - Before filing, verify that the impact narrative, PoC, and every
      non-None CVSS impact metric describe the same demonstrated
      consequence. When evidence is incomplete, lower the metric or
      continue validation; never choose a higher value "to be safe."

    Automatic LLM-based **deduplication** rejects reports that describe
    the same root cause on the same asset as an existing report. If you
    get a ``duplicate_of`` response, do NOT retry — move on to other
    areas. When you have learned something a filed finding does not yet
    carry, revise that finding with ``update_vulnerability_report``
    instead of filing this report again.

    **Counterevidence pass (required before filing)**: actively build the
    strongest case that this finding is NOT exploitable, or less severe
    than you think — then record the result in ``counterevidence``, set
    ``confidence`` honestly, and state what would move the severity in
    ``severity_change_conditions``. These three fields are mandatory and
    validated. A finding you could not execute is at best
    ``confidence: medium``, with the gap named in
    ``confidence_rationale``.

    **Report output rules** (this content may be rendered into generated
    reports):

    - No internal/system details: never mention paths like
      ``/workspace``, internal tools, agents, sandboxes, models, system
      prompts, internal errors / stack traces, or tester environment.
      Never leak internal identifiers (proxy request IDs, internal
      report IDs) into any field.
    - Tone: formal, objective, third-person, vendor-neutral, concise.
      Avoid internal-guidance headings like "QUICK", "Approach", or
      "Techniques" that read like an engineering runbook rather than a
      client deliverable.
    - **Use markdown in every text field**: ``**bold**`` for emphasis,
      ``inline code`` for identifiers/values/parameters, and fenced
      code blocks (```` ```language ````) for any code/payload/HTTP
      excerpt. Never leave code bare/unformatted. When referencing a
      file, annotate the fence, e.g.
      ```` ```python title=app.py startLineNumber=42 endLineNumber=50 ````.
    - Field discipline: ``poc_description`` is steps only — NO code (all
      code goes in ``poc_script_code``); ``remediation_steps`` is prose
      only — NO code/diffs (code fixes go in ``code_locations``).
    - Numbered steps allowed only in PoC and Remediation sections.
    - Avoid hedging language; be precise and non-vague.
    - Follow a standard pentest report structure across the fields:
      (1) overview (``description``), (2) severity & CVSS vector
      (``cvss_breakdown``), (3) affected asset(s) (``target`` /
      ``endpoint``), (4) technical details (``technical_analysis``),
      (5) proof of concept (``poc_description`` + ``poc_script_code``),
      (6) impact (``impact``), (7) evidence (``evidence``), and
      (8) remediation (``remediation_steps``).

    **White-box requirement**: when source is available, you MUST
    populate ``code_locations``. See the ``code_locations`` arg below
    for the full rules around ``fix_before`` / ``fix_after``,
    multi-part fixes, and informational-vs-actionable entries.

    **CVSS breakdown** is an object with all 8 metrics (each a single
    uppercase letter):

    - ``attack_vector``: ``N`` (Network), ``A`` (Adjacent), ``L``
      (Local), ``P`` (Physical)
    - ``attack_complexity``: ``L`` / ``H``
    - ``privileges_required``: ``N`` / ``L`` / ``H``
    - ``user_interaction``: ``N`` / ``R``
    - ``scope``: ``U`` (Unchanged) / ``C`` (Changed)
    - ``confidentiality`` / ``integrity`` / ``availability``: ``N`` /
      ``L`` / ``H``

    Derive the vector from the demonstrated attack, not the finding
    category or a scanner/template severity:

    - ``C:L`` requires actual access to some restricted information.
      Reconnaissance value alone is ``C:N``. ``C:H`` requires total
      disclosure or limited disclosure with a direct serious impact,
      such as a usable administrator credential or private key.
    - ``I:L`` requires demonstrated unauthorized, limited modification;
      ``I:H`` requires total or directly serious modification. Otherwise
      use ``I:N``.
    - ``A:L`` requires demonstrated performance degradation or service
      interruption; ``A:H`` requires complete or directly serious
      denial of the affected service. Otherwise use ``A:N``.
    - Use ``S:C`` only when exploitation demonstrably crosses into a
      component governed by a different security authority. A separate
      backend, downstream effect, or third-party name is insufficient.

    Example::

        {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H"
        }

    **CVSS calibration** — score the weakness you actually proved, not a
    hypothetical worst case. Most over-rating comes from these mistakes:

    - **Don't presuppose a separate compromise.** If exploitation
      requires the attacker to already hold a victim secret (a stolen
      session cookie/token, a leaked one-time link, intercepted traffic),
      that acquisition is not free. Do not score it as
      ``privileges_required:N`` with ``attack_complexity:L`` as if
      directly reachable, and do not rate a replay-of-captured-secret
      issue High/Critical unless the *same* finding demonstrates a
      concrete way to obtain that secret. Issues like a session that
      survives logout or a replayable link are session-management /
      defense-in-depth weaknesses — usually Low/Medium on their own.
    - **Reserve ``H`` impact for demonstrated broad impact.** ``C:H`` /
      ``I:H`` require proof of wide or systemic read/write. A single
      user's data, a read-only information leak, or merely confirming
      that an account / domain / software version *exists* (enumeration)
      is ``C:L`` (often ``I:N``) — not ``C:H``.
    - **Model required position and interaction honestly.** An
      adversary-in-the-middle prerequisite (e.g. cleartext transmission)
      or a required victim action is not guaranteed — reflect it in
      ``attack_complexity`` / ``user_interaction`` instead of assuming the
      ideal condition always holds.

    **CVE / CWE rules**: pass the bare ID only (``CVE-2024-1234``,
    ``CWE-89``) — no name, no parenthetical. Be 100% certain; if
    unsure, use ``web_search`` to verify the ID before passing, or omit
    the field entirely. Always prefer the most specific child CWE over
    a broad parent (CWE-89 not CWE-74; CWE-78 not CWE-77). Do NOT use
    broad/parent CWEs like CWE-74, CWE-20, CWE-200, CWE-284, or
    CWE-693.

    Common CWE references (use the ID only — names are listed here
    just for your lookup):

    - **Injection**: CWE-79 XSS, CWE-89 SQLi, CWE-78 OS Command
      Injection, CWE-94 Code Injection, CWE-77 Command Injection.
    - **Auth / Access**: CWE-287 Improper Authentication, CWE-862
      Missing Authorization, CWE-863 Incorrect Authorization, CWE-306
      Missing Auth for Critical Function, CWE-639 Authz Bypass via
      User-Controlled Key.
    - **Web**: CWE-352 CSRF, CWE-918 SSRF, CWE-601 Open Redirect,
      CWE-434 Unrestricted File Upload.
    - **Memory**: CWE-787 OOB Write, CWE-125 OOB Read, CWE-416 UAF,
      CWE-120 Classic Buffer Overflow.
    - **Data**: CWE-502 Deserialization of Untrusted Data, CWE-22
      Path Traversal, CWE-611 XXE.
    - **Crypto / Config**: CWE-798 Hard-coded Credentials, CWE-327
      Broken / Risky Crypto, CWE-311 Missing Encryption, CWE-916 Weak
      Password Hashing.

    Args:
        title: Specific finding title (e.g.
            ``"SQL Injection in /api/users login parameter"``). Don't
            include the CVE number in the title.
        description: Concise, non-technical TL;DR of the vulnerability
            (1-3 sentences) — it appears first in the report. Deep
            technical detail and root-cause analysis belong in
            ``technical_analysis``, not here.
        impact: The unauthorized result demonstrated by the PoC, the
            affected data or operation, and its scope. Keep plausible
            but unverified follow-on risks separate; do not use them to
            set CVSS metrics.
        target: Affected URL / domain / repository.
        technical_analysis: The mechanism and root cause.
        poc_description: Step-by-step reproduction (steps only, no code).
        poc_script_code: Working PoC (Python preferred).
        remediation_steps: Specific, actionable fix (prose, no code).
        evidence: Concrete proof the issue is real and exploitable —
            request/response excerpts, observed behavior, tool output.
            Use fenced code blocks; no internal identifiers/paths.
        assumptions: Short note on the assumptions/prerequisites that
            make this finding impactful or exploitable (e.g. "assumes an
            authenticated low-privilege user").
        counterevidence: REQUIRED. The strongest case *against* this
            finding, after actively looking for it — the guard you might
            have missed, the deployment constraint, the precondition. If
            you genuinely found nothing, say what you checked (e.g. "no
            input validation, WAF, or authorization check found on this
            path; tested authenticated and unauthenticated"), not just
            "none". A generic trust claim ("the framework escapes this")
            is not counterevidence unless you confirmed that specific
            call in this context.
        confidence: REQUIRED. Your calibrated confidence that this is a
            real, exploitable issue: ``high`` (working PoC against the
            live target, or a complete reachable source→sink trace),
            ``medium`` (strong static evidence you could not fully
            execute), or ``low`` (plausible with a material unresolved
            gap). Do not inflate — an accurate ``medium`` is more useful
            than a ``high`` that fails triage.
        confidence_rationale: Required when ``confidence`` is not
            ``high``. Name the specific gap (e.g. "static-only trace,
            could not stand up the service to reproduce"; "reachability
            of this route from unauthenticated traffic unconfirmed").
        severity_change_conditions: REQUIRED. One concrete sentence on
            what single piece of additional evidence would raise or
            lower the severity (e.g. "confirmation this route is exposed
            to unauthenticated internet traffic would raise this to
            critical").
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``.
        cvss_breakdown: 8-metric object per the format above.
        endpoint: API path / Git path (e.g. ``/api/login``).
        method: HTTP method when relevant.
        cve: ``CVE-YYYY-NNNNN`` if certain, else omit.
        cwe: ``CWE-NNN`` (most specific child) if certain, else omit.
        code_locations: White-box findings — list of location objects.
        http_exchange_ids: Proxy request IDs that prove this finding.
            Copy these IDs from ``list_requests`` or ``view_request``.
            For a finding validated over HTTP, capture and inspect the
            supporting exchanges and include their IDs here before filing.
            Include relevant baseline/control requests as well as the exploit.
            Omit only when the finding has no captured HTTP evidence (for
            example a static-only code finding). Never invent IDs or drop
            them to bypass a verification error; retry the capture instead.
            If the result carries a ``warning`` that the IDs were not
            stored, the finding is filed without them: attach them with
            ``update_vulnerability_report`` once the proxy responds.
            Keep IDs out of ``evidence`` and all other report text.

            **How ``fix_before`` / ``fix_after`` work**: they're used as
            literal GitHub/GitLab PR suggestion blocks. When a reviewer
            accepts the suggestion, the platform replaces the **exact
            lines from ``start_line`` to ``end_line``** with
            ``fix_after``. Therefore:

            1. ``fix_before`` must be a **VERBATIM** copy of the source
               at those lines — same whitespace, indentation, line
               breaks. If it doesn't match character-for-character, the
               suggestion will corrupt the code when accepted.
            2. ``fix_after`` is the COMPLETE replacement for that
               entire block (may be more or fewer lines).
            3. ``start_line`` / ``end_line`` must precisely cover the
               lines in ``fix_before`` — no more, no less.

            **Multi-part fixes**: many fixes touch multiple
            non-contiguous parts of a file (e.g. add an import at the
            top AND change code lower down). Since each
            ``fix_before`` / ``fix_after`` pair covers ONE contiguous
            block, create **separate location entries** for each
            non-contiguous part. Use ``label`` to describe each part's
            role (``"Add escape helper import"``, ``"Sanitize input
            before SQL"``). Order primary fix first, supporting
            changes (imports, config) after.

            **Informational vs actionable**:
            - With ``fix_before`` / ``fix_after``: actionable fix
              (renders as a PR suggestion block).
            - Without them: informational context (e.g. showing the
              source of tainted data, or a sink that doesn't need
              direct editing).

            **Per-location fields**:
            - ``file`` (REQUIRED): path **relative** to repo root. No
              leading slash, no ``..``, no ``/workspace/`` prefix.
              Right: ``"src/db/queries.ts"``. Wrong:
              ``"/workspace/repo/src/db/queries.ts"``, ``"./src/x.py"``,
              ``"../../etc/passwd"``.
            - ``start_line`` (REQUIRED): 1-based; positive integer.
              Verify against the actual file — do NOT guess.
            - ``end_line`` (REQUIRED): 1-based; ``>= start_line``.
              Only equal to ``start_line`` when the block truly is one
              line.
            - ``snippet`` (optional): verbatim source at this range.
            - ``label`` (optional): short role description; especially
              important for multi-part fixes.
            - ``fix_before`` (optional): verbatim copy of the
              vulnerable code, lines ``start_line``-``end_line``.
            - ``fix_after`` (optional): complete replacement for that
              block; syntactically valid.

            **Common mistakes to avoid**:
            - Guessing line numbers instead of reading the file.
            - Paraphrasing / reformatting code in ``fix_before``.
            - Setting ``start_line == end_line`` when the vulnerable
              code spans multiple lines.
            - Bundling an import addition and a far-away code change
              into one location — split them.
            - Padding ``fix_before`` with surrounding context lines
              that aren't part of the fix.
            - Duplicating the same change across multiple locations.
        fix_verification: REQUIRED whenever any ``code_locations`` entry
            carries a ``fix_after``. A reviewer can apply that
            suggestion with one click, so an unverified fix ships
            straight into the codebase. Before writing this field, work
            the gates **in order** and never trade an earlier one for a
            later one:

            1. **Security closure** — re-trace the source → sink path
               through the *patched* code and state why it is now
               blocked. Re-run the PoC against the fix if you can.
            2. **Bypass review** — re-read the diff *without* leaning on
               the rationale that produced it. Name the sibling call
               sites, equivalent sinks, and alternate malicious input
               classes you checked, and try at least one.
            3. **Preserved behavior** — name the legitimate inputs,
               public APIs, and error semantics that must keep working,
               and confirm the patch leaves them intact. A fix that
               breaks the feature is not a fix.
            4. **Repository checks** — run the narrowest relevant
               syntax / type / lint / test check that covers the
               changed lines.

            Then write what you did: the commands you ran and their
            results, and every gate you could only reason about rather
            than execute, marked explicitly as a gap. Do not claim a
            gate passed because it looks right. If a gate fails, revise
            the patch or drop ``fix_after`` and leave the location
            informational — never compensate for a failed security
            closure with a smaller diff or extra prose.

            Also use this field to record the narrowest-complete-change
            judgement: prefer the smallest repository-native fix that
            fully enforces the invariant, using existing helpers, with
            no unrelated refactors folded in.
        fix_pr_body: Optional. When source is available and you have a
            concrete fix, a markdown PR-description body proposing the
            fix (summary + rationale). Prose/markdown only — the code
            change itself belongs in ``code_locations``. Omit for
            black-box findings.

    Example (abbreviated — mirror this structure)::

        title: "Reflected XSS in /search q parameter"
        description:
            The **`q`** parameter of `/search` reflects user input into
            the HTML response without encoding, allowing script
            injection.
        technical_analysis:
            The handler interpolates `q` directly into the page body:

            ```python title=views.py startLineNumber=42 endLineNumber=44
            html = f"<h2>Results for {q}</h2>"
            return HttpResponse(html)
            ```

            No output encoding is applied, so `<script>` executes.
        poc_description:
            1. Navigate to `/search?q=<payload>`.
            2. Observe the payload executes in the victim's browser.
        poc_script_code:
            ```
            GET /search?q=<script>alert(document.domain)</script>
            ```
        evidence:
            Response echoes the payload verbatim:

            ```html
            <h2>Results for <script>alert(document.domain)</script></h2>
            ```
        assumptions:
            Assumes a victim can be induced to open a crafted link.
        remediation_steps:
            Context-encode all user input rendered into HTML; prefer the
            template engine's auto-escaping over string interpolation.
        counterevidence:
            No output encoding, CSP, or WAF observed on this response;
            payload executed in a current browser. The parameter is
            reflected on an unauthenticated route, so no privileged
            position is required.
        confidence: "high"
        severity_change_conditions:
            A restrictive CSP that blocks inline script execution would
            reduce impact and lower the severity.
        fix_effort: "low"
    """
    (
        http_exchange_ids,
        http_exchange_errors,
        http_exchange_warning,
    ) = await _verify_http_exchange_ids(ctx, http_exchange_ids)
    if http_exchange_errors:
        return json.dumps(
            {
                "success": False,
                "error": "Validation failed",
                "errors": http_exchange_errors,
            },
            ensure_ascii=False,
            default=str,
        )

    agent_id, agent_name = _caller_identity(ctx)

    result = await _do_create(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        evidence=evidence,
        assumptions=assumptions,
        counterevidence=counterevidence,
        confidence=confidence,
        confidence_rationale=confidence_rationale,
        severity_change_conditions=severity_change_conditions,
        fix_effort=fix_effort,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
        http_exchange_ids=http_exchange_ids,
        fix_verification=fix_verification,
        fix_pr_body=fix_pr_body,
        agent_id=agent_id,
        agent_name=agent_name,
        report_state=_report_state_from_context(ctx),
    )
    return json.dumps(_with_warning(result, http_exchange_warning), ensure_ascii=False, default=str)


@function_tool(timeout=60, strict_mode=False)
async def update_vulnerability_report(
    ctx: RunContextWrapper,
    report_id: str,
    update_reason: str,
    title: str | None = None,
    description: str | None = None,
    impact: str | None = None,
    target: str | None = None,
    technical_analysis: str | None = None,
    poc_description: str | None = None,
    poc_script_code: str | None = None,
    remediation_steps: str | None = None,
    evidence: str | None = None,
    assumptions: str | None = None,
    counterevidence: str | None = None,
    confidence: str | None = None,
    confidence_rationale: str | None = None,
    severity_change_conditions: str | None = None,
    fix_effort: str | None = None,
    cvss_breakdown: dict[str, str] | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    http_exchange_ids: list[str] | None = None,
    fix_verification: str | None = None,
    fix_pr_body: str | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> str:
    """Revise a vulnerability report that is already filed, keeping its id.

    Use this when you learn something a filed finding does not yet carry:

    - You built the working exploit after filing the finding on static
      evidence, so the PoC and the confidence change.
    - You chained the finding with another one and the real impact is
      higher, so the impact narrative and the CVSS vector change.
    - Further testing narrowed or weakened the finding, so the severity
      must come down.
    - Counterevidence, remediation, or a code location was wrong or
      incomplete.

    This is not deduplication. You do not need a duplicate verdict to
    revise your own finding, and you must not file a second report for a
    finding you can revise. Call ``list_reports`` or ``get_report`` first
    to find the id and read what the report already says.

    Pass only the fields you want to replace. Every other field stays as
    it is. Reporting rules of ``create_vulnerability_report`` apply to
    every field you pass, including the markdown and tone rules.

    Notes on specific fields:

    - ``cvss_breakdown`` replaces the whole vector. The score and the
      severity are recalculated from it, so pass all 8 metrics. On a
      dependency finding it replaces the contextual rating and needs
      ``contextual_cvss_reasoning`` with it. Pass the reasoning alone to
      correct only the explanation of the rating already on file.
    - A dependency finding never carries ``endpoint``, ``method`` or a PoC.
      File a proven exploit of the package as its own report.
    - A field that only explains another field is dropped when the field
      it explains changes and you pass no replacement. Pass
      ``confidence_rationale`` with a new ``confidence``, and
      ``severity_change_conditions`` with a new ``cvss_breakdown``.
    - ``code_locations`` replaces the whole list. A location carrying
      ``fix_after`` needs ``fix_verification``.

    The report keeps its id, its original author, and its filing time. The
    revision is recorded in the report as update history, so state the
    reason plainly.

    Args:
        report_id: Id of the report to revise (format ``vuln-NNNN``).
        update_reason: What you learned that the report does not yet
            carry, in one or two sentences.
        title: Replacement title.
        description: Replacement overview.
        impact: Replacement impact narrative.
        target: Replacement affected asset.
        technical_analysis: Replacement technical details.
        poc_description: Replacement PoC steps (no code).
        poc_script_code: Replacement exploit script or payload.
        remediation_steps: Replacement remediation prose (no code).
        evidence: Replacement evidence.
        assumptions: Replacement exploitability prerequisites.
        counterevidence: Replacement case against the finding.
        confidence: ``high`` / ``medium`` / ``low``.
        confidence_rationale: The gap behind a confidence below ``high``.
        severity_change_conditions: What would move the severity now.
        fix_effort: ``trivial`` / ``low`` / ``medium`` / ``high``.
        cvss_breakdown: All 8 CVSS metrics. Replaces the score and the
            severity too.
        endpoint: Replacement endpoint.
        method: Replacement HTTP method.
        cve: Replacement CVE id.
        cwe: Replacement CWE id.
        code_locations: Replacement code locations.
        http_exchange_ids: Replacement proxy request ids. Pass an empty
            list to remove all linked exchanges.
        fix_verification: Verification statement for an applyable fix.
        fix_pr_body: Replacement fix PR body.
        contextual_cvss_reasoning: Dependency findings only. What you
            observed in this codebase that justifies the contextual
            ``cvss_breakdown``.
    """
    (
        http_exchange_ids,
        http_exchange_errors,
        http_exchange_warning,
    ) = await _verify_http_exchange_ids(ctx, http_exchange_ids)
    if http_exchange_errors:
        return json.dumps(
            {
                "success": False,
                "error": "Validation failed",
                "errors": http_exchange_errors,
            },
            ensure_ascii=False,
            default=str,
        )

    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "evidence": evidence,
        "assumptions": assumptions,
        "counterevidence": counterevidence,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "severity_change_conditions": severity_change_conditions,
        "fix_effort": fix_effort,
        "cvss_breakdown": cvss_breakdown,
        "endpoint": endpoint,
        "method": method,
        "cve": cve,
        "cwe": cwe,
        "code_locations": code_locations,
        "http_exchange_ids": http_exchange_ids,
        "fix_verification": fix_verification,
        "fix_pr_body": fix_pr_body,
        "contextual_cvss_reasoning": contextual_cvss_reasoning,
    }
    if http_exchange_warning and all(value is None for value in fields.values()):
        return json.dumps(
            {"success": False, "error": http_exchange_warning, "report_id": report_id},
            ensure_ascii=False,
            default=str,
        )

    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _do_update,
        report_id=report_id,
        update_reason=update_reason,
        fields=fields,
        agent_id=agent_id,
        agent_name=agent_name,
        report_state=_report_state_from_context(ctx),
    )
    return json.dumps(_with_warning(result, http_exchange_warning), ensure_ascii=False, default=str)
