"""Provider-independent failure taxonomy."""

from typing import Literal


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

NON_RETRYABLE_FAILURES: frozenset[FailureKind] = frozenset(
    {"authentication", "billing", "policy", "incompatible"}
)
