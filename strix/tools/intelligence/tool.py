"""Agent-facing vulnerability intelligence lookup."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.paths import run_dir_for
from strix.intel import query_intelligence


@function_tool(timeout=60)
async def query_vulnerability_intel(
    ctx: RunContextWrapper,
    identifier: str,
    ecosystem: str = "",
    version: str = "",
) -> str:
    """Look up current CVE or package-version intelligence from first-party feeds.

    The result is enrichment, not proof that the target is vulnerable. Confirm
    the affected version and exploitability before creating a finding.

    Args:
        identifier: Exact CVE ID, or exact package name when ecosystem/version are set.
        ecosystem: OSV ecosystem such as PyPI, npm, Go, Maven, or crates.io.
        version: Exact installed package version for OSV matching.
    """
    inner: dict[str, Any] = ctx.context if isinstance(ctx.context, dict) else {}
    scan_id = str(inner.get("scan_id") or "")
    cache_dir = run_dir_for(scan_id) / ".state" / "intel" if scan_id else None
    result = await asyncio.to_thread(
        query_intelligence,
        identifier,
        ecosystem=ecosystem,
        version=version,
        cache_dir=cache_dir,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
