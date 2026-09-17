"""Read-only environment diagnostics shared by optional integrations.

Provider credentials are discovered by provider adapters in Strix v2.  This
module deliberately contains no startup gate or configuration mutation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from strix.config.settings import IntegrationSettings


def _missing_web_search_vars(integrations: IntegrationSettings) -> list[str]:
    """Return credential hints required by the selected web-search backend."""
    if integrations.web_search_provider == "exa":
        return [] if integrations.exa_api_key else ["EXA_API_KEY"]
    if integrations.web_search_provider == "perplexity":
        return [] if integrations.perplexity_api_key else ["PERPLEXITY_API_KEY"]
    if integrations.exa_api_key or integrations.perplexity_api_key:
        return []
    return ["EXA_API_KEY", "PERPLEXITY_API_KEY"]
