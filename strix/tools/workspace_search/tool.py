"""Agent-facing deterministic workspace search tool."""

from __future__ import annotations

import json
import posixpath
from typing import Any, Literal

from agents import RunContextWrapper, function_tool

from strix.tools.workspace_search.engine import build_rg_args, parse_rg_json


SearchMode = Literal["fixed", "regex"]


def _workspace_path(path: str) -> str:
    raw = path.strip() or "/workspace"
    if not raw.startswith("/"):
        raw = f"/workspace/{raw}"
    normalized = posixpath.normpath(raw)
    if normalized != "/workspace" and not normalized.startswith("/workspace/"):
        raise ValueError("path must stay inside /workspace")
    return normalized


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else str(value or "")


@function_tool(timeout=60)
async def workspace_search(
    ctx: RunContextWrapper,
    query: str,
    mode: SearchMode = "fixed",
    path: str = "/workspace",
    globs: list[str] | None = None,
    case_sensitive: bool | None = None,
    whole_word: bool = False,
    include_hidden: bool = False,
    max_results: int = 100,
) -> str:
    """Search workspace code with ripgrep and return bounded line-level matches.

    Use this before reading files when the task is to find exact text, a symbol,
    a route, a setting, or a regex pattern. ``fixed`` is the safe default and
    treats punctuation literally; use ``regex`` only when regex behavior is
    intentional. Results contain paths, line/column numbers, and short snippets,
    so read only the relevant ranges afterward instead of loading whole files.

    Args:
        query: Exact text or regex to locate.
        mode: ``fixed`` for literal text or ``regex`` for a regular expression.
        path: Directory inside ``/workspace``. Relative paths are rooted there.
        globs: Optional ripgrep include/exclude globs, e.g. ``["*.py", "!tests/**"]``.
        case_sensitive: True/False, or null for ripgrep smart-case behavior.
        whole_word: Require word boundaries around the match.
        include_hidden: Include hidden files while always excluding ``.git``.
        max_results: Maximum returned matching lines, from 1 to 200.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    session = inner.get("sandbox_session")
    if session is None:
        return json.dumps(
            {"success": False, "error": "sandbox session is unavailable"},
            ensure_ascii=False,
        )
    try:
        root = _workspace_path(path)
        args = build_rg_args(
            query=query,
            root=root,
            mode=mode,
            globs=globs,
            case_sensitive=case_sensitive,
            whole_word=whole_word,
            include_hidden=include_hidden,
            max_results=max_results,
        )
        result = await session.exec(*args, timeout=30)
        exit_code = getattr(result, "exit_code", 1)
        if exit_code not in {0, 1}:
            detail = _decode(getattr(result, "stderr", "")).strip()[:1_000]
            return json.dumps(
                {
                    "success": False,
                    "error": detail or f"ripgrep exited with code {exit_code}",
                },
                ensure_ascii=False,
            )
        payload = parse_rg_json(
            _decode(getattr(result, "stdout", "")),
            query=query,
            root=root,
            mode=mode,
            max_results=max_results,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        payload = {"success": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - tool failures are model-readable results
        payload = {"success": False, "error": f"workspace search failed: {exc}"}
    return json.dumps(payload, ensure_ascii=False, default=str)
