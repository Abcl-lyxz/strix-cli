"""Strix application settings.

Public surface:

- :class:`Settings` — composite model. Get via :func:`load_settings`.
- :class:`LlmSettings`, :class:`RuntimeSettings`,
  :class:`IntegrationSettings` — sub-models, attribute-accessed off
  ``Settings``.
- :func:`load_settings` — memoized resolve (env > JSON file > defaults).
- :func:`apply_config_override` — switch the JSON source to a custom path.
- :func:`persist_current` — write currently-set env vars to the active file.
- :func:`persist_overrides` — write explicit values from an interactive client.
"""

from strix.config.loader import (
    apply_config_override,
    config_path,
    load_settings,
    migrate_legacy_config_secrets,
    persist_current,
    persist_overrides,
    read_config_document,
    write_config_document,
)
from strix.config.settings import (
    ContextSettings,
    DedupeSettings,
    IntegrationSettings,
    LlmSettings,
    RoutingSettings,
    RuntimeSettings,
    Settings,
)


__all__ = [
    "ContextSettings",
    "DedupeSettings",
    "IntegrationSettings",
    "LlmSettings",
    "RoutingSettings",
    "RuntimeSettings",
    "Settings",
    "apply_config_override",
    "config_path",
    "load_settings",
    "migrate_legacy_config_secrets",
    "persist_current",
    "persist_overrides",
    "read_config_document",
    "write_config_document",
]
