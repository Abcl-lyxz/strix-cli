"""Compatibility import for the shared application controller."""

import sys

from strix.interface import application
from strix.interface.application import TuiController


sys.modules[__name__] = application
__all__ = ["TuiController"]
