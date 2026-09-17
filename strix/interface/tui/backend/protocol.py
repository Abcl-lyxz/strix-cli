"""Versioned JSON protocol shared with the Go TUI."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


PROTOCOL_VERSION: Literal[8] = 8
PROTOCOL_CAPABILITIES = (
    "state-revisions",
    "collection-deltas",
    "structured-command-errors",
    "agents-collection",
    "interactive-configuration",
    "large-user-prompts",
    "model-route-pools",
    "notification-inbox",
    "storage-locations",
    "workspace-forms",
    "attachments",
    "provider-discovery",
    "provider-adapters-v2",
    "automatic-task-router",
    "read-only-viewer",
    "typed-command-results",
)

# Commands and control messages are intentionally small. Event and finding
# history uses a separate bounded collection stream so a resumed run can be
# larger than any individual frame.
MAX_COMMAND_BYTES = 512 * 1024
MAX_COLLECTION_FRAME_BYTES = 4 * 1024 * 1024


class ProtocolHandshakeError(RuntimeError):
    """Raised before the Go TUI is activated when protocol negotiation fails."""


class CommandRequest(BaseModel):
    """Source-of-truth schema for a TUI command request."""

    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)


class CommandError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: Literal[
        "invalid_request",
        "persistence_error",
        "command_failed",
        "protocol_error",
        "internal_error",
        "result_too_large",
    ]
    message: str
    retryable: bool = False


class CommandResult(BaseModel):
    """Source-of-truth schema for every Python-to-Go command result."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    command: str
    result: dict[str, Any] = Field(default_factory=dict)
    error: CommandError | None = None


class ProtocolEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[8] = PROTOCOL_VERSION
    type: str
    request_id: str | None = None
    payload: dict[str, Any]


def protocol_json_schema() -> dict[str, Any]:
    return ProtocolEnvelope.model_json_schema(
        ref_template="#/$defs/{model}",
    ) | {
        "x-command-request": CommandRequest.model_json_schema(),
        "x-command-result": CommandResult.model_json_schema(),
    }


def envelope(
    message_type: str,
    payload: dict[str, Any],
    *,
    request_id: str | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {
        "version": PROTOCOL_VERSION,
        "type": message_type,
        "payload": payload,
    }
    if request_id:
        message["request_id"] = request_id
    return message
