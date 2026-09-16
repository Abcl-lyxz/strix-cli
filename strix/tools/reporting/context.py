"""SDK-context translation for reporting tools."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents import RunContextWrapper

    from strix.ports.reporting import ReportRepository


def caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    """Return the identity of the agent invoking a reporting tool."""

    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name: Any = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None
    return agent_id, agent_name


def report_repository(ctx: RunContextWrapper) -> ReportRepository | None:
    """Resolve the run-owned repository supplied by the composition root."""

    inner = ctx.context if isinstance(ctx.context, dict) else {}
    scan_context = inner.get("scan_context")
    return getattr(scan_context, "report_state", None)
