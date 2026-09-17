"""Resolve runtime routes exclusively from the Strix v3 application config."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config.app_config import ConfigService, get_config_service
from strix.providers import get_provider_registry
from strix.providers.policy import quality_tier


if TYPE_CHECKING:
    from strix.domain.routes import RouteConfig


def load_app_routes(service: ConfigService | None = None) -> list[RouteConfig]:
    config = (service or get_config_service()).load()
    registry = get_provider_registry()
    routes: list[RouteConfig] = []
    for model in config.models.values():
        if not model.enabled:
            continue
        connection = config.connections.get(model.connection_id)
        if connection is None or not connection.enabled:
            continue
        route = registry.adapter(connection.provider_id).build_model(connection, model)
        route.supports_tools = model.supports_tools
        route.supports_vision = model.supports_vision
        route.supports_reasoning = model.supports_reasoning
        route.quality_tier = (
            quality_tier(model.provider_id, model.adapter_id, model.model_id)
            if model.quality_tier == "unknown"
            else model.quality_tier
        )
        route.input_cost_per_million = model.input_cost_per_million
        route.output_cost_per_million = model.output_cost_per_million
        route.connection_revision = connection.revision
        routes.append(route)
    if not routes:
        raise ValueError("No enabled Strix v2 models are configured. Use /connect, then /models.")
    return routes


def app_route_revision(service: ConfigService | None = None) -> int:
    return (service or get_config_service()).load().revision


__all__ = ["app_route_revision", "load_app_routes"]
