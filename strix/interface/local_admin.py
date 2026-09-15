"""Local route, secret, and notification administration commands."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
from typing import Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from rich.console import Console
from rich.table import Table

from strix.config import codex, config_path, migrate_legacy_config_secrets
from strix.config.provider_catalog import provider_descriptors, refresh_provider_catalog
from strix.config.providers import connect_provider, discover_models
from strix.config.routes import (
    delete_route_key,
    list_saved_routes,
    remove_route,
    routing_strategy,
    save_route,
    set_route_enabled,
    set_route_key,
)
from strix.intel import refresh_intelligence
from strix.intel import status as intelligence_status
from strix.notifications import Notification, get_notification_service, notify
from strix.routing import RouteConfig, RoutedModel, RoutePool
from strix.security import get_secret_store
from strix.tools.mcp.loader import load_user_mcp_configs


def run_routes(argv: list[str]) -> int:  # noqa: PLR0911, PLR0912, PLR0915
    parser = argparse.ArgumentParser(prog="strix routes")
    sub = parser.add_subparsers(dest="command", required=True)
    list_parser = sub.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    for command in ("add", "edit"):
        route_parser = sub.add_parser(command)
        route_parser.add_argument("name")
        route_parser.add_argument("--model", required=command == "add")
        route_parser.add_argument("--base-url")
        route_parser.add_argument("--priority", type=int)
        route_parser.add_argument("--max-concurrency", type=int)
        route_parser.add_argument("--rpm", type=int)
        route_parser.add_argument("--tpm", type=int)
    for command in ("remove", "enable", "disable", "test"):
        route_parser = sub.add_parser(command)
        route_parser.add_argument("name")
    key_parser = sub.add_parser("key")
    key_parser.add_argument("name")
    key_parser.add_argument("--delete", action="store_true")
    sub.add_parser("strategy")
    args = parser.parse_args(argv)
    console = Console()

    if args.command == "list":
        routes = list_saved_routes()
        if args.json:
            console.print_json(data=[route.public_dict() for route in routes])
        else:
            _print_routes(console, routes)
        return 0
    if args.command == "strategy":
        console.print(f"Routing strategy: [#60a5fa]{routing_strategy()}[/]")
        return 0
    if args.command == "key":
        if args.delete:
            if not delete_route_key(args.name):
                console.print(f"[yellow]No stored key for route {args.name}.[/]")
                return 1
        else:
            value = getpass.getpass(f"API key for {args.name}: ")
            if not value:
                console.print("[red]API key cannot be empty.[/]")
                return 2
            set_route_key(args.name, value)
        console.print(f"[#22c55e]Updated credentials for route {args.name}.[/]")
        return 0
    if args.command == "remove":
        return _route_boolean(console, remove_route(args.name), args.name, "removed")
    if args.command in {"enable", "disable"}:
        enabled = args.command == "enable"
        return _route_boolean(
            console,
            set_route_enabled(args.name, enabled),
            args.name,
            "enabled" if enabled else "disabled",
        )
    if args.command == "test":
        route = _find_route(args.name)
        try:
            asyncio.run(_test_route(route))
        except Exception as exc:  # noqa: BLE001 - providers expose varied errors
            notify(
                "runtime.route.test_failed",
                title=f"Route {route.name} test failed",
                detail=str(exc),
                severity="error",
                route_id=route.name,
                dedupe_key=f"route-test:{route.name}",
            )
            console.print(f"[red]Route test failed:[/] {exc}")
            return 1
        console.print(f"[#22c55e]Route {route.name} is ready.[/]")
        return 0

    existing = _find_route(args.name) if args.command == "edit" else None
    route = RouteConfig(
        name=args.name,
        model=args.model or (existing.model if existing else ""),
        base_url=args.base_url
        if args.base_url is not None
        else getattr(existing, "base_url", None),
        priority=args.priority if args.priority is not None else getattr(existing, "priority", 1),
        max_concurrency=(
            args.max_concurrency
            if args.max_concurrency is not None
            else getattr(existing, "max_concurrency", 2)
        ),
        rpm=args.rpm if args.rpm is not None else getattr(existing, "rpm", None),
        tpm=args.tpm if args.tpm is not None else getattr(existing, "tpm", None),
        enabled=getattr(existing, "enabled", True),
    )
    save_route(route, replace=args.command == "edit")
    console.print(f"[#22c55e]Route {route.name} saved.[/]")
    return 0


def run_providers(argv: list[str]) -> int:
    """Discover providers/models without sending an inference request."""
    parser = argparse.ArgumentParser(prog="strix providers")
    sub = parser.add_subparsers(dest="command", required=True)
    list_parser = sub.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    refresh_parser = sub.add_parser("refresh")
    refresh_parser.add_argument("--force", action="store_true")
    for command in ("detect", "models"):
        detect = sub.add_parser(command)
        detect.add_argument("provider", nargs="?", default="custom")
        detect.add_argument("--base-url", default="")
        detect.add_argument("--profile", default="")
        detect.add_argument("--refresh", action="store_true")
    connect = sub.add_parser("connect")
    connect.add_argument("provider")
    connect.add_argument("model")
    connect.add_argument("--name")
    connect.add_argument("--base-url", default="")
    connect.add_argument("--no-key", action="store_true")
    connect.add_argument("--session-only", action="store_true")
    args = parser.parse_args(argv)
    console = Console()
    if args.command == "list":
        values = provider_descriptors()
        if args.json:
            console.print_json(data=values)
        else:
            table = Table("Provider", "Adapter", "Transport", "Default endpoint")
            for item in values:
                table.add_row(
                    item["name"],
                    item["adapter_id"],
                    item["transport"],
                    item.get("base_url") or "operator supplied",
                )
            console.print(table)
        return 0
    if args.command == "refresh":
        result = refresh_provider_catalog(force=args.force)
        console.print(f"Provider catalog: {result['source']} ({result['path']})")
        return 0
    if args.command in {"detect", "models"}:
        result = discover_models(
            args.provider,
            base_url=args.base_url,
            profile=args.profile,
            refresh=args.refresh,
        )
        console.print_json(data=result)
        return 0 if result.get("models") else 1
    api_key = "" if args.no_key else getpass.getpass(f"API key for {args.provider}: ")
    result = connect_provider(
        {
            "provider_id": args.provider,
            "model_id": args.model,
            "name": args.name or args.provider,
            "base_url": args.base_url,
            "api_key": api_key,
            "persist": not args.session_only,
        }
    )
    console.print(f"Connected model route [#22c55e]{result['name']}[/].")
    return 0


def run_intel(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="strix intel")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    update = sub.add_parser("update")
    update.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    value = (
        intelligence_status()
        if args.command == "status"
        else refresh_intelligence(force=args.force)
    )
    Console().print_json(data=value)
    return 0


def run_secrets(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="strix secrets")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("migrate")
    sub.add_parser("purge-legacy")
    args = parser.parse_args(argv)
    console = Console()
    store = get_secret_store()
    if args.command == "status":
        console.print(f"Credential backend: [#60a5fa]{store.backend_name}[/]")
        console.print(f"Available: {'yes' if store.available else 'no'}")
        console.print(f"Config: {config_path()}")
        return 0 if store.available else 1

    report = _migrate_every_secret_source()
    failed = report["failed"]
    if failed:
        console.print("[yellow]Some credentials could not be migrated; originals were retained.[/]")
        for item in failed:
            console.print(f"  [dim]·[/] {item}")
        return 1
    if args.command == "purge-legacy":
        # Migration itself is verification-first and performs the safe purge.
        console.print("[#22c55e]Verified credential references; legacy plaintext was removed.[/]")
    else:
        console.print("[#22c55e]Credential migration complete.[/]")
    return 0


def run_notifications(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="strix notifications")
    sub = parser.add_subparsers(dest="command", required=True)
    list_parser = sub.add_parser("list")
    list_parser.add_argument("--unread", action="store_true")
    list_parser.add_argument("--severity", choices=["info", "warning", "error", "critical"])
    list_parser.add_argument("--category")
    list_parser.add_argument("--run")
    list_parser.add_argument("--agent")
    list_parser.add_argument("--route")
    list_parser.add_argument("--json", action="store_true")
    for command in ("read", "dismiss"):
        action_parser = sub.add_parser(command)
        action_parser.add_argument("id")
    sub.add_parser("clear")
    args = parser.parse_args(argv)
    service = get_notification_service()
    console = Console()
    if args.command == "list":
        notifications = service.list(
            unread=True if args.unread else None,
            severity=args.severity,
            category=args.category,
            run_id=args.run,
            agent_id=args.agent,
            route_id=args.route,
        )
        if args.json:
            console.print_json(data=[item.to_dict() for item in notifications])
        else:
            _print_notifications(console, notifications)
        return 0
    if args.command == "clear":
        count = service.clear_read()
        console.print(f"Cleared {count} read notification(s).")
        return 0
    if args.command == "dismiss":
        return 0 if service.dismiss(args.id) else 1
    notification = service.get(args.id)
    if notification is None:
        console.print("[red]Notification not found.[/]")
        return 1
    service.mark_read(args.id)
    _print_notification(console, notification)
    return 0


def _migrate_every_secret_source() -> dict[str, list[str]]:
    report = migrate_legacy_config_secrets()
    failed = list(report["failed"])
    for label, migrate in (
        ("ChatGPT OAuth", _migrate_codex),
        ("MCP bearer tokens", load_user_mcp_configs),
    ):
        try:
            migrate()
        except Exception:  # noqa: BLE001 - independent credential formats
            failed.append(label)
    return {"migrated": list(report["migrated"]), "failed": failed}


def _migrate_codex() -> Any:
    return codex.read_record()


async def _test_route(route: RouteConfig) -> None:
    pool = RoutePool([route], wait_timeout=15)
    model = RoutedModel(pool)
    try:
        await model.get_response(
            system_instructions="You are a connection test.",
            input="Reply with OK.",
            model_settings=ModelSettings(include_usage=True),
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    finally:
        await pool.close()


def _find_route(name: str) -> RouteConfig:
    route = next(
        (route for route in list_saved_routes() if route.name.casefold() == name.casefold()),
        None,
    )
    if route is None:
        raise ValueError(f"unknown route: {name}")
    return route


def _route_boolean(console: Console, changed: bool, name: str, verb: str) -> int:
    if not changed:
        console.print(f"[red]Unknown route:[/] {name}")
        return 1
    console.print(f"[#22c55e]Route {name} {verb}.[/]")
    return 0


def _print_routes(console: Console, routes: list[RouteConfig]) -> None:
    table = Table(title="Model routes", header_style="bold #22c55e")
    for heading in ("Name", "Model", "Priority", "Concurrency", "Limits", "Key", "State"):
        table.add_column(heading)
    for route in routes:
        limits = (
            "/".join(
                item
                for item in (
                    f"{route.rpm} RPM" if route.rpm else "",
                    f"{route.tpm} TPM" if route.tpm else "",
                )
                if item
            )
            or "—"
        )
        table.add_row(
            route.name,
            route.model,
            str(route.priority),
            str(route.max_concurrency),
            limits,
            "stored" if route.api_key_ref else "—",
            "enabled" if route.enabled else "disabled",
        )
    console.print(table)


def _print_notifications(console: Console, notifications: list[Notification]) -> None:
    if not notifications:
        console.print("[dim]No notifications.[/]")
        return
    for item in notifications:
        marker = "●" if item.unread else "○"
        console.print(
            f"{marker} [{item.severity}] {item.title} "
            f"[dim]({item.id[:8]}, {item.category}, x{item.count})[/]"
        )


def _print_notification(console: Console, item: Notification) -> None:
    console.print(f"[{item.severity}] {item.title}")
    if item.detail:
        console.print(item.detail)
    console.print(json.dumps(item.to_dict(), indent=2))


__all__ = ["run_intel", "run_notifications", "run_providers", "run_routes", "run_secrets"]
