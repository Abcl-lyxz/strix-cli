"""Backend bridge for external TUI clients."""

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from strix.interface.application import TuiController
    from strix.interface.tui.backend.server import TuiBackendServer


def __getattr__(name: str) -> Any:
    if name == "TuiController":
        from strix.interface.application import TuiController  # noqa: PLC0415

        return TuiController
    if name == "TuiBackendServer":
        from strix.interface.tui.backend.server import TuiBackendServer  # noqa: PLC0415

        return TuiBackendServer
    raise AttributeError(name)


__all__ = ["TuiBackendServer", "TuiController"]
