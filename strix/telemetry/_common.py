"""Local version and diagnostic phase metadata."""

from importlib.metadata import PackageNotFoundError, version


_scan_phase = "startup"


def get_version() -> str:
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        return "unknown"


def set_scan_phase(phase: str) -> None:
    global _scan_phase  # noqa: PLW0603
    _scan_phase = phase


def get_scan_phase() -> str:
    return _scan_phase
