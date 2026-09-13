"""Local diagnostics only. Strix does not send usage analytics."""

import logging as std_logging

from ._common import set_scan_phase


def report_error(error_type: str, exc: BaseException | None = None) -> None:
    std_logging.getLogger(__name__).debug(
        "%s: %s", error_type, type(exc).__name__ if exc else "error"
    )


__all__ = ["report_error", "set_scan_phase"]
