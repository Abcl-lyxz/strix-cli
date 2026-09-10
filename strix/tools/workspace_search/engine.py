"""Shared ripgrep engine used by the agent tool and the TUI.

The engine asks ripgrep for JSON rather than parsing ``path:line:text`` output,
which keeps Windows paths, Unicode, and text containing colons unambiguous.
Only a bounded projection is returned to callers; an exact lookup should never
fill an agent context with a repository-sized result.
"""

from __future__ import annotations

import base64
import json
import subprocess
from typing import TYPE_CHECKING, Any, Literal


if TYPE_CHECKING:
    from pathlib import Path


SearchMode = Literal["fixed", "regex"]

MAX_QUERY_CHARS = 1_024
MAX_RESULTS = 200
MAX_GLOBS = 16
MAX_SNIPPET_CHARS = 500


def _validate_search(
    query: str,
    mode: SearchMode,
    globs: list[str] | None,
    max_results: int,
) -> tuple[str, list[str]]:
    if not isinstance(query, str) or not query:
        raise ValueError("query must be a non-empty string")
    if len(query) > MAX_QUERY_CHARS:
        raise ValueError(f"query must be at most {MAX_QUERY_CHARS} characters")
    if mode not in {"fixed", "regex"}:
        raise ValueError("mode must be 'fixed' or 'regex'")
    if not isinstance(max_results, int) or isinstance(max_results, bool):
        raise TypeError("max_results must be an integer")
    if not 1 <= max_results <= MAX_RESULTS:
        raise ValueError(f"max_results must be between 1 and {MAX_RESULTS}")

    normalized_globs = list(globs or [])
    if len(normalized_globs) > MAX_GLOBS:
        raise ValueError(f"no more than {MAX_GLOBS} globs may be supplied")
    for pattern in normalized_globs:
        if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
            raise ValueError("each glob must be a non-empty string of at most 256 characters")
    return query, normalized_globs


def build_rg_args(
    *,
    query: str,
    root: str,
    mode: SearchMode = "fixed",
    globs: list[str] | None = None,
    case_sensitive: bool | None = None,
    whole_word: bool = False,
    include_hidden: bool = False,
    max_results: int = 100,
) -> list[str]:
    """Return an injection-safe argv vector for a bounded code search."""
    query, normalized_globs = _validate_search(query, mode, globs, max_results)
    args = [
        "rg",
        "--json",
        "--line-number",
        "--column",
        "--no-messages",
        "--max-columns",
        "1000",
        "--max-columns-preview",
        "--max-filesize",
        "5M",
    ]
    if mode == "fixed":
        args.append("--fixed-strings")
    if case_sensitive is True:
        args.append("--case-sensitive")
    elif case_sensitive is False:
        args.append("--ignore-case")
    else:
        args.append("--smart-case")
    if whole_word:
        args.append("--word-regexp")
    if include_hidden:
        args.extend(("--hidden", "--glob", "!.git/**"))
    for pattern in normalized_globs:
        args.extend(("--glob", pattern))
    # ``--`` makes a query such as ``--help`` data rather than an rg option.
    args.extend(("--", query, root))
    return args


def _rg_text(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    text = value.get("text")
    if isinstance(text, str):
        return text
    encoded = value.get("bytes")
    if not isinstance(encoded, str):
        return ""
    try:
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _display_path(path: str, root: str) -> str:
    normalized_root = root.rstrip("/\\")
    for separator in ("/", "\\"):
        prefix = normalized_root + separator
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def parse_rg_json(
    output: str,
    *,
    query: str,
    root: str,
    mode: SearchMode,
    max_results: int,
) -> dict[str, Any]:
    """Parse ripgrep's JSON stream into a small stable result schema."""
    matches: list[dict[str, Any]] = []
    total = 0
    for raw_line in output.splitlines():
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get("type") != "match":
            continue
        data = record.get("data")
        if not isinstance(data, dict):
            continue
        path = _rg_text(data.get("path"))
        line_text = _rg_text(data.get("lines")).rstrip("\r\n")
        submatches = data.get("submatches")
        first = submatches[0] if isinstance(submatches, list) and submatches else {}
        start = first.get("start", 0) if isinstance(first, dict) else 0
        line_number = data.get("line_number", 0)
        total += 1
        if len(matches) >= max_results:
            continue
        matches.append(
            {
                "path": _display_path(path, root)[:1_024],
                "line": line_number if isinstance(line_number, int) else 0,
                "column": start + 1 if isinstance(start, int) else 1,
                "text": line_text[:MAX_SNIPPET_CHARS],
            }
        )

    return {
        "success": True,
        "query": query,
        "mode": mode,
        "root": root,
        "match_count": total,
        "returned_count": len(matches),
        "truncated": total > len(matches),
        "matches": matches,
    }


def _decode_stream(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else str(value or "")


def search_local_workspace(
    root: Path,
    query: str,
    *,
    mode: SearchMode = "fixed",
    globs: list[str] | None = None,
    case_sensitive: bool | None = None,
    whole_word: bool = False,
    include_hidden: bool = False,
    max_results: int = 50,
    timeout: float = 15,
) -> dict[str, Any]:
    """Search a host-side directory for the interactive TUI."""
    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        raise ValueError(f"workspace search root is not a directory: {resolved}")
    args = build_rg_args(
        query=query,
        root=".",
        mode=mode,
        globs=globs,
        case_sensitive=case_sensitive,
        whole_word=whole_word,
        include_hidden=include_hidden,
        max_results=max_results,
    )
    try:
        completed = subprocess.run(  # noqa: S603
            args,
            cwd=resolved,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("ripgrep (rg) is required for workspace search") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"workspace search timed out after {timeout:g}s") from exc
    if completed.returncode not in {0, 1}:
        detail = _decode_stream(completed.stderr).strip()[:1_000]
        raise RuntimeError(detail or f"ripgrep exited with code {completed.returncode}")
    result = parse_rg_json(
        completed.stdout,
        query=query,
        root=".",
        mode=mode,
        max_results=max_results,
    )
    result["root"] = str(resolved)
    return result
