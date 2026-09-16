"""Resolve scan-owned artifact repositories from model-tool context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from agents import RunContextWrapper

    from strix.application.context import ScanContext
    from strix.ports.artifacts import ArtifactRepository


def scan_context_from_tool(ctx: RunContextWrapper[Any]) -> ScanContext:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    scan_context = inner.get("scan_context")
    if scan_context is None:
        raise RuntimeError("This tool requires a scan context")
    return cast("ScanContext", scan_context)


def artifact_store_from_tool(
    ctx: RunContextWrapper[Any], name: str
) -> ArtifactRepository:
    return scan_context_from_tool(ctx).artifact_store(name)
