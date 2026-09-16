"""Report/finding helpers."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from strix.report.state import ReportState


if TYPE_CHECKING:
    from strix.report.dedupe import check_duplicate

__all__ = [
    "ReportState",
    "check_duplicate",
]


def __getattr__(name: str) -> Any:
    # check_duplicate pulls in the agents SDK import graph, so it resolves
    # lazily: importing this package must stay lightweight and never enter
    # that graph (the import warm-up thread may be walking it concurrently).
    if name == "check_duplicate":
        return import_module("strix.report.dedupe").check_duplicate
    raise AttributeError(name)
