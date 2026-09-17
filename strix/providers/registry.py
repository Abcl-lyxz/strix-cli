"""Provider adapter registry with explicit plugin validation."""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

from strix.providers.builtin import builtin_adapters


if TYPE_CHECKING:
    from strix.config.app_config import ConnectionProfile
    from strix.providers.base import ProviderAdapter, ProviderDefinition


logger = logging.getLogger(__name__)


class ProviderRegistry:
    def __init__(self, *, load_plugins: bool = True) -> None:
        self._adapters: dict[str, ProviderAdapter] = {}
        for adapter in builtin_adapters():
            self.register(adapter)
        if load_plugins:
            self._load_plugins()

    def register(self, adapter: ProviderAdapter) -> None:
        if getattr(adapter, "api_version", None) != 2:
            raise ValueError("Provider adapter api_version must be 2")
        definition = adapter.definition()
        if definition.id in self._adapters:
            raise ValueError(f"Duplicate provider adapter: {definition.id}")
        self._adapters[definition.id] = adapter

    def _load_plugins(self) -> None:
        try:
            points = entry_points(group="strix.providers")
        except TypeError:  # pragma: no cover - compatibility with older importlib metadata
            points = entry_points().select(group="strix.providers")
        for point in points:
            try:
                loaded: Any = point.load()
                adapter = loaded() if isinstance(loaded, type) else loaded
                self.register(adapter)
            except Exception:  # one optional plugin must not hide built-ins
                logger.exception("Ignoring invalid provider plugin %s", point.name)

    def adapter(self, provider_id: str) -> ProviderAdapter:
        try:
            return self._adapters[provider_id]
        except KeyError as exc:
            raise ValueError(
                f"Provider '{provider_id}' has no compatible adapter. Install a Strix provider "
                "plugin or use Custom OpenAI-compatible."
            ) from exc

    def definitions(self) -> list[ProviderDefinition]:
        return sorted(
            (adapter.definition() for adapter in self._adapters.values()),
            key=lambda item: (item.id == "custom", item.name.casefold()),
        )

    def detected_connections(self) -> list[ConnectionProfile]:
        result: dict[str, ConnectionProfile] = {}
        for adapter in self._adapters.values():
            for profile in adapter.detect_connections():
                result[profile.id] = profile
        return sorted(result.values(), key=lambda item: item.name.casefold())


_registry: ProviderRegistry | None = None


def get_provider_registry() -> ProviderRegistry:
    global _registry  # noqa: PLW0603
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry


def set_provider_registry(registry: ProviderRegistry | None) -> None:
    global _registry  # noqa: PLW0603
    _registry = registry


__all__ = ["ProviderRegistry", "get_provider_registry", "set_provider_registry"]
