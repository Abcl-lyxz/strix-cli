"""Pure Strix domain types.

Modules in this package intentionally depend only on the Python standard
library.  Runtime SDKs, persistence, configuration, and presentation belong to
ports or adapters instead.
"""

from strix.domain.events import DomainEvent
from strix.domain.execution import ExecutionPhase, ExecutionState
from strix.domain.failures import FailureKind
from strix.domain.findings import CreateFinding, FindingMutation, ReviseFinding
from strix.domain.recovery import (
    RecoveryAction,
    RecoveryDecision,
    RecoveryLimits,
    TurnRecoveryState,
)
from strix.domain.routes import RouteConfig


__all__ = [
    "CreateFinding",
    "DomainEvent",
    "ExecutionPhase",
    "ExecutionState",
    "FailureKind",
    "FindingMutation",
    "RecoveryAction",
    "RecoveryDecision",
    "RecoveryLimits",
    "ReviseFinding",
    "RouteConfig",
    "TurnRecoveryState",
]
