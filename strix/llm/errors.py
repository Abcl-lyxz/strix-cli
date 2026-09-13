"""Shared provider failure classification for routing, execution, and UI."""

from __future__ import annotations

from typing import Literal

from strix.llm.tool_arguments import InvalidToolArgumentsError


FailureKind = Literal[
    "transient",
    "authentication",
    "billing",
    "context",
    "policy",
    "incompatible",
    "malformed",
    "fatal",
]


def classify_model_failure(error: BaseException) -> FailureKind:  # noqa: PLR0911 - ordered classification
    from strix.config import codex  # noqa: PLC0415 - config models use this classifier

    if codex.is_content_guardrail_error(error):
        return "policy"
    text = str(error).lower()
    status = getattr(error, "status_code", None)
    if isinstance(error, InvalidToolArgumentsError) or any(
        marker in text
        for marker in (
            "arguments must be valid json",
            "arguments` must be a valid json",
            "arguments must be a valid json",
            "invalid json input for tool",
        )
    ):
        return "malformed"
    if any(
        marker in text
        for marker in ("content policy", "content filter", "guardrail", "safety policy")
    ):
        return "policy"
    if status == 402 or any(
        marker in text
        for marker in (
            "billing",
            "insufficient quota",
            "quota exceeded",
            "payment required",
            "credit balance",
        )
    ):
        return "billing"
    if status in {401, 403} or any(
        marker in text for marker in ("invalid api key", "incorrect api key", "unauthorized")
    ):
        return "authentication"
    if any(
        marker in text
        for marker in (
            "context length",
            "context window",
            "context_length_exceeded",
            "prompt is too long",
            "input is too long",
            "too many tokens",
        )
    ):
        return "context"
    if status in {400, 404, 422} and any(
        marker in text
        for marker in (
            "invalid tool",
            "tool schema",
            "unsupported tool",
            "does not support tools",
            "function calling is not supported",
            "model not found",
            "unsupported parameter",
        )
    ):
        return "incompatible"
    if (
        status in {408, 409, 425, 429}
        or (isinstance(status, int) and 500 <= status <= 599)
        or isinstance(error, TimeoutError | ConnectionError | OSError)
        or any(
            marker in type(error).__name__.lower()
            for marker in ("timeout", "connection", "ratelimit", "serviceunavailable")
        )
    ):
        return "transient"
    return "fatal"
