"""Connect to MCP servers so a run can reach their tools on demand.

Given one :class:`McpConnectionConfig` per server, :func:`connect_mcp_servers`
connects each server, counts the tools it offers (honoring the connection's
allowlist), and returns the live sessions. It does NOT register anything as an
agent tool: under the generic-dispatch model the run holds these sessions in a
per-run :class:`~strix.tools.mcp.registry.McpRegistry`, and the agent reaches
them through the two dispatch tools (``describe_mcp`` / ``call_mcp``), which call
:func:`dispatch_mcp_call` here to run one tool and serialize its result.

A server that cannot connect is logged and skipped, so one bad connection never
fails the run.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, NamedTuple

from strix.tools.mcp import transport as mcp_transport
from strix.tools.mcp.session import McpConnectionUnavailableError, SupervisedMcpSession


if TYPE_CHECKING:
    from strix.tools.mcp.config import McpConnectionConfig
    from strix.tools.mcp.registry import McpConnectionRequest, McpRegistry


logger = logging.getLogger(__name__)


class ConnectedMcpServer(NamedTuple):
    """One successfully connected MCP connection and how many tools it offers.

    ``session`` is the :class:`~strix.tools.mcp.session.SupervisedMcpSession` that
    owns the live connection on its own task, so the caller cleans it up when the
    run ends (``await session.aclose()``) and hands it to the run's
    :class:`~strix.tools.mcp.registry.McpRegistry`; ``name`` and ``tool_count``
    let the caller show the user a startup summary and fill the prompt inventory;
    ``notes`` carries the connection's optional free-text description so the
    caller can surface it as the connection's purpose in the inventory.
    """

    session: SupervisedMcpSession
    name: str
    tool_count: int
    notes: str | None = None


async def _count_session_tools(config: McpConnectionConfig, session: SupervisedMcpSession) -> int:
    """Count a connected session's reachable tools for the startup summary.

    ``allowed_tools`` of ``None`` counts every listed tool; a list counts only
    those names. The count matches what ``describe_mcp`` will show, because the
    static tool filter built in :func:`_build_server` restricts the server's own
    ``list_tools`` to the same allowlist. The listing goes through the session's
    owning task like every other call.
    """
    allowed = config.allowed_tools
    mcp_tools = await session.list_tools()
    return sum(1 for mcp_tool in mcp_tools if allowed is None or mcp_tool.name in allowed)


async def connect_mcp_servers(
    configs: list[McpConnectionConfig],
) -> list[ConnectedMcpServer]:
    """Connect each MCP config on its own supervising task and return the sessions.

    Each connection becomes a :class:`~strix.tools.mcp.session.SupervisedMcpSession`
    that owns ``connect()``, the held-open session, and ``cleanup()`` on one
    dedicated task, so a later background failure in one session is contained to
    that task and never cancels the run. Returns one :class:`ConnectedMcpServer`
    per session that connected, carrying the session (the caller closes it with
    ``await session.aclose()`` when the run ends and hands it to the run's
    registry) plus the connection name, tool count, and notes. A connection whose
    initial connect fails is skipped rather than raised (fail-open).

    If this coroutine is itself cancelled mid-attach (the run going down), every
    session started so far is closed on its own task before the cancellation is
    re-raised, so nothing is orphaned.

    Nothing is registered as an agent tool: the caller builds a per-run
    :class:`~strix.tools.mcp.registry.McpRegistry` from these sessions, and the
    agent reaches each tool on demand through ``describe_mcp`` / ``call_mcp``.
    """
    connected: list[ConnectedMcpServer] = []
    sessions: list[SupervisedMcpSession] = []
    try:
        for config in configs:
            session = SupervisedMcpSession(config, server_builder=mcp_transport.build_server)
            sessions.append(session)
            if not await session.start():
                # Initial connect failed; already logged inside the session. Drop it.
                await session.aclose()
                sessions.remove(session)
                continue
            try:
                tool_count = await _count_session_tools(config, session)
            except McpConnectionUnavailableError:
                # The session died between connecting and its first listing; skip it.
                logger.warning("MCP connection %r died before its first listing", config.name)
                await session.aclose()
                sessions.remove(session)
                continue
            logger.info("Connected MCP server %r (%d tools)", config.name, tool_count)
            connected.append(
                ConnectedMcpServer(
                    session=session, name=config.name, tool_count=tool_count, notes=config.notes
                )
            )
    except BaseException:
        # Cancelled or errored mid-attach: close every session started so far,
        # each on its own task, then re-raise. The runner only receives the list
        # on a clean return, so on an abnormal exit this function owns the cleanup.
        for session in sessions:
            with contextlib.suppress(BaseException):
                await session.aclose()
        raise

    return connected


async def attach_mcp_requests(
    requests: list[McpConnectionRequest],
    registry: McpRegistry,
) -> list[ConnectedMcpServer]:
    """Connect a caller's MCP requests and populate the run's registry.

    The one shared attach-and-populate path both the command-line and the
    SaaS/pro product go through, so all connecting and cleanup lives in one owner.
    The caller supplies inert :class:`McpConnectionRequest` objects (a config plus
    a provider label, an optional per-connection ``result_transform``, and an
    optional ``purpose``) and never a live session: the engine connects each
    config here, reusing :func:`connect_mcp_servers` so the fail-open behavior (a
    connection that will not connect is logged and skipped) and the cancellation
    cleanup are preserved unchanged.

    For each connection that came up, this registers it under its config name with
    its tool count, its ``provider`` label, its ``result_transform``, and a purpose
    of ``request.purpose`` when set else the connection's notes. Returns the
    connected servers (the runner records them and cleans them up when the run
    ends).
    """
    request_by_name = {request.config.name: request for request in requests}
    connections = await connect_mcp_servers([request.config for request in requests])
    for connection in connections:
        request = request_by_name[connection.name]
        registry.add(
            name=connection.name,
            session=connection.session,
            tool_count=connection.tool_count,
            purpose=request.purpose or connection.notes,
            provider=request.provider,
            result_transform=request.result_transform,
        )
    return connections
