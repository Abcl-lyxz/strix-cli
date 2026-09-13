"""Strict tool arguments and a lossless, provider-safe history projection."""

from __future__ import annotations

import json
import math
from collections import defaultdict, deque
from typing import Any, cast


class InvalidToolArgumentsError(ValueError):
    """Arguments must be regenerated, never guessed or executed."""


def _constant(value: str) -> None:
    raise InvalidToolArgumentsError(f"Non-standard JSON constant: {value}")


def _finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise InvalidToolArgumentsError("JSON numbers must be finite")
    if isinstance(value, dict):
        for child in cast("dict[str, Any]", value).values():
            _finite(child)
    elif isinstance(value, list):
        for child in cast("list[object]", value):
            _finite(child)


def parse_tool_arguments(raw: Any) -> dict[str, Any]:
    """Parse a strict JSON object, including numbers that overflow float64."""
    try:
        value = json.loads(raw, parse_constant=_constant)
        if not isinstance(value, dict):
            raise InvalidToolArgumentsError("Tool arguments must be a JSON object")
        _finite(value)
    except (ValueError, TypeError, RecursionError) as exc:
        raise InvalidToolArgumentsError(
            "Tool arguments must be a valid, finite JSON object"
        ) from exc
    return cast("dict[str, Any]", value)


def quarantine_history(items: list[Any]) -> tuple[list[Any], bool]:
    """Replace invalid structured calls and their outputs with diagnostic text.

    The original items remain untouched, including the durable transcript. Pair
    by occurrence, not just ID: gateways sometimes reuse IDs within a turn.
    Completed output is retained as context and is never scheduled for replay.
    """
    pending: dict[str, deque[bool]] = defaultdict(deque)
    result: list[Any] = []
    changed = False
    for raw_item in items:
        if not isinstance(raw_item, dict):
            result.append(raw_item)
            continue
        item = cast("dict[str, Any]", raw_item)
        kind, call_id = item.get("type"), str(item.get("call_id", ""))
        invalid = False
        if kind == "function_call":
            try:
                parse_tool_arguments(item.get("arguments"))
            except InvalidToolArgumentsError:
                invalid = True
            pending[call_id].append(invalid)
            if invalid:
                result.append(
                    {
                        "role": "user",
                        "content": (
                            "[Tool history recovery] The recorded "
                            f"{item.get('name', 'unknown')} call "
                            "had invalid JSON arguments and was quarantined. Do not assume it ran. "
                            "Any recorded result follows; do not repeat completed actions. "
                            "Use a valid JSON object for future calls."
                        ),
                    }
                )
                changed = True
                continue
        elif kind == "function_call_output" and pending[call_id]:
            invalid = pending[call_id].popleft()
            if invalid:
                output = item.get("output", "")
                text = output if isinstance(output, str) else json.dumps(output, default=str)
                result.append({"role": "user", "content": "[Recorded tool result] " + text})
                changed = True
                continue
        result.append(item)
    return result, changed


def safe_model_input(value: str | list[Any]) -> str | list[Any]:
    return value if isinstance(value, str) else quarantine_history(value)[0]
