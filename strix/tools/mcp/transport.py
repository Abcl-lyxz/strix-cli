"""MCP transport adapter shared by connection setup and session supervision."""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from agents.mcp import (
    MCPServer,
    MCPServerStdio,
    MCPServerStdioParams,
    MCPServerStreamableHttp,
    MCPServerStreamableHttpParams,
    create_static_tool_filter,
)
from mcp.client.stdio import stdio_client
from mcp.shared._httpx_utils import create_mcp_http_client

from strix.tools.mcp.failures import HttpStatusRecorder


if TYPE_CHECKING:
    import httpx

    from strix.tools.mcp.config import McpConnectionConfig


type ResultTransform = Callable[[str, Any], Any]


class BuiltMcpServer(NamedTuple):
    server: MCPServer
    recorder: HttpStatusRecorder | None


type ServerBuilder = Callable[[McpConnectionConfig], BuiltMcpServer]


def _auth_headers(config: McpConnectionConfig) -> dict[str, str]:
    auth = config.auth
    if auth is None:
        return {}
    if not auth.token:
        raise ValueError("MCP bearer credential could not be resolved")
    return {"Authorization": f"Bearer {auth.token}"}


@contextlib.asynccontextmanager
async def _quiet_stdio_streams(params: Any) -> AsyncIterator[Any]:
    with Path(os.devnull).open("w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as streams:
            yield streams


class _QuietMCPServerStdio(MCPServerStdio):
    def create_streams(self) -> Any:
        return _quiet_stdio_streams(self.params)


def build_server(config: McpConnectionConfig) -> BuiltMcpServer:
    """Construct, but do not connect, one SDK MCP transport."""

    tool_filter = (
        create_static_tool_filter(allowed_tool_names=config.allowed_tools)
        if config.allowed_tools is not None
        else None
    )
    if config.transport == "stdio":
        stdio_params: MCPServerStdioParams = {
            "command": cast("str", config.command),
            "args": config.args,
            "env": config.env,
        }
        return BuiltMcpServer(
            _QuietMCPServerStdio(
                params=stdio_params,
                name=config.name,
                tool_filter=tool_filter,
                cache_tools_list=True,
            ),
            None,
        )

    recorder = HttpStatusRecorder()

    def httpx_client_factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        client = create_mcp_http_client(headers=headers, timeout=timeout, auth=auth)
        client.event_hooks.setdefault("response", []).append(recorder)
        return client

    http_params: MCPServerStreamableHttpParams = {
        "url": cast("str", config.url),
        "headers": _auth_headers(config),
        "timeout": config.http_timeout_seconds,
        "sse_read_timeout": config.sse_read_timeout_seconds,
        "httpx_client_factory": httpx_client_factory,
    }
    return BuiltMcpServer(
        MCPServerStreamableHttp(
            params=http_params,
            name=config.name,
            tool_filter=tool_filter,
            cache_tools_list=True,
            client_session_timeout_seconds=config.session_timeout_seconds,
        ),
        recorder,
    )


def _mcp_result_to_tool_output(server: MCPServer, result: Any) -> Any:
    if getattr(server, "use_structured_content", False) and result.structuredContent:
        return json.dumps(result.structuredContent)
    outputs: list[dict[str, Any]] = []
    for item in result.content:
        if item.type == "text":
            outputs.append({"type": "text", "text": item.text})
        elif item.type == "image":
            outputs.append(
                {"type": "image", "image_url": f"data:{item.mimeType};base64,{item.data}"}
            )
        else:
            outputs.append({"type": "text", "text": str(item.model_dump(mode="json"))})
    return outputs[0] if len(outputs) == 1 else outputs


async def dispatch_mcp_call(
    server: MCPServer,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    label: str,
    result_transform: ResultTransform | None = None,
) -> Any:
    """Invoke one MCP tool and normalize its SDK-facing result."""

    result = await server.call_tool(tool_name, arguments)
    if result_transform is not None:
        return result_transform(label, result.model_dump(mode="json"))
    tool_output = _mcp_result_to_tool_output(server, result)
    return errored_tool_output(tool_output) if getattr(result, "isError", False) else tool_output


def errored_tool_output(tool_output: Any) -> dict[str, Any]:
    if isinstance(tool_output, dict):
        return {**tool_output, "success": False}
    return {"success": False, "content": tool_output}
