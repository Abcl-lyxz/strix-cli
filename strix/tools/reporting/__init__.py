"""Model-facing reporting tools composed from focused adapters."""

from strix.tools.reporting.dependencies import create_dependency_report
from strix.tools.reporting.queries import get_report, list_reports
from strix.tools.reporting.vulnerabilities import (
    create_vulnerability_report,
    update_vulnerability_report,
)


__all__ = [
    "create_dependency_report",
    "create_vulnerability_report",
    "get_report",
    "list_reports",
    "update_vulnerability_report",
]
