"""Compatibility import for the shared lifecycle and terminal transport."""

import sys

from strix.interface import application_runtime
from strix.interface.application_runtime import GoTuiPreActivationError, GoTuiRuntime, run_go_tui


sys.modules[__name__] = application_runtime
__all__ = ["GoTuiPreActivationError", "GoTuiRuntime", "run_go_tui"]
