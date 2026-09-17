"""Read-only installation, Docker, model, and network diagnostics."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import sys
from typing import Any
from urllib.parse import urlsplit

import docker
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import load_settings
from strix.config.app_config import AppConfigError, get_config_service
from strix.interface.cli_args import get_version
from strix.interface.docker_cli import find_docker_cli
from strix.providers import get_provider_registry


_PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def _check(
    name: str,
    status: str,
    detail: str,
    *,
    fix: str | None = None,
) -> dict[str, str]:
    result = {"name": name, "status": status, "detail": detail}
    if fix:
        result["fix"] = fix
    return result


def _is_wsl() -> bool:
    release = platform.release().lower()
    return "microsoft" in release or "wsl" in release


def _safe_endpoint(value: str) -> str:
    """Return a proxy/daemon endpoint without embedded credentials."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "configured (value could not be parsed)"
    if not parsed.scheme or not parsed.hostname:
        return value
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    with contextlib.suppress(ValueError):
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}"


def _docker_cli_fix() -> str:
    if platform.system() == "Windows":
        return (
            "Install Docker Desktop, or run Strix inside the same WSL distribution "
            "where Docker Engine is installed."
        )
    if _is_wsl():
        return "Install Docker Engine in this WSL distribution and start the docker service."
    return "Install Docker Engine and ensure the docker command is on PATH."


def _docker_connection_fix(environ: dict[str, str]) -> str:
    docker_host = environ.get("DOCKER_HOST", "").strip()
    if docker_host.lower().startswith(("tcp://", "http://", "https://")):
        return (
            f"DOCKER_HOST points to {_safe_endpoint(docker_host)}. VPN/firewall changes often "
            "break remote TCP endpoints. Prefer running Strix beside Docker and using the local "
            "Unix socket or Windows named pipe; if TCP is required, secure it with TLS."
        )
    if platform.system() == "Windows":
        return (
            "Start Docker Desktop and verify `docker version`. If Docker is installed only in "
            "WSL, install and run Strix in that WSL distribution instead."
        )
    return "Start Docker Engine and verify `docker version` as the current user."


def _proxy_check(environ: dict[str, str]) -> dict[str, str]:
    configured = [
        f"{name}={_safe_endpoint(environ[name])}"
        for name in _PROXY_NAMES
        if environ.get(name, "").strip()
    ]
    if not configured:
        return _check("Proxy", "pass", "No HTTP proxy variables are set")

    loopback = False
    for name in _PROXY_NAMES:
        value = environ.get(name, "").strip()
        if not value:
            continue
        with contextlib.suppress(ValueError):
            loopback = urlsplit(value).hostname in {"127.0.0.1", "localhost", "::1"}
        if loopback:
            break
    detail = ", ".join(configured)
    if loopback:
        return _check(
            "Proxy",
            "warn",
            detail,
            fix=(
                "A loopback proxy must be running in this same environment. Containers cannot "
                "reach the host's 127.0.0.1; unset stale proxy variables or configure a reachable "
                "proxy endpoint and NO_PROXY entries."
            ),
        )
    return _check("Proxy", "pass", detail)


def collect_diagnostics(
    *,
    check_network: bool = False,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Collect diagnostics without changing Docker, Strix, or model configuration."""
    env = dict(os.environ if environ is None else environ)
    checks: list[dict[str, str]] = [
        _check("Strix", "pass", f"version {get_version()} via {sys.executable}"),
        _check("Python", "pass", platform.python_version()),
        _proxy_check(env),
    ]

    docker_host = env.get("DOCKER_HOST", "").strip()
    if docker_host:
        endpoint_status = "pass"
        endpoint_fix = None
        if docker_host.lower().startswith(("tcp://", "http://")) and not env.get(
            "DOCKER_TLS_VERIFY"
        ):
            endpoint_status = "warn"
            endpoint_fix = (
                "An unauthenticated Docker TCP endpoint is equivalent to host-level access. "
                "Prefer the local Unix socket/named pipe, or enable mutual TLS."
            )
        checks.append(
            _check(
                "Docker endpoint",
                endpoint_status,
                _safe_endpoint(docker_host),
                fix=endpoint_fix,
            )
        )
    else:
        endpoint = "Windows named pipe" if platform.system() == "Windows" else "local Unix socket"
        checks.append(_check("Docker endpoint", "pass", endpoint))

    docker_cli = find_docker_cli(env)
    if docker_cli is None:
        checks.append(_check("Docker CLI", "fail", "not found on PATH", fix=_docker_cli_fix()))
    else:
        checks.append(_check("Docker CLI", "pass", docker_cli))

    client: Any | None = None
    image_present = False
    settings: Any | None = None
    try:
        app_config = get_config_service().load()
        enabled_models = [model for model in app_config.models.values() if model.enabled]
        if app_config.connections and enabled_models:
            checks.append(
                _check(
                    "Provider routing",
                    "pass",
                    (
                        f"{len(app_config.connections)} saved connection(s), "
                        f"{len(enabled_models)} enabled model(s)"
                    ),
                )
            )
        else:
            detected = {
                definition.name
                for definition in get_provider_registry().definitions()
                if any(env.get(name, "").strip() for name in definition.env)
            }
            hint = (
                f"; detected environment hints for {', '.join(sorted(detected))}"
                if detected
                else ""
            )
            checks.append(
                _check(
                    "Provider routing",
                    "warn",
                    f"No complete saved connection/model route{hint}",
                    fix="Open Strix and use /connect, then /models.",
                )
            )
    except AppConfigError as exc:
        checks.append(
            _check(
                "Provider routing",
                "fail",
                str(exc),
                fix="Repair config.json before starting a scan.",
            )
        )
    except Exception as exc:
        checks.append(_check("Provider routing", "warn", f"configuration could not be read: {exc}"))

    try:
        settings = load_settings()
    except Exception as exc:
        settings = None
        checks.append(_check("Runtime settings", "warn", f"could not be read: {exc}"))

    try:
        client = docker.from_env(environment=env)
        client.ping()
        version = client.version().get("Version", "unknown")
        checks.append(_check("Docker daemon", "pass", f"reachable (engine {version})"))

        if settings is not None:
            image = str(settings.runtime.image)
            try:
                client.images.get(image)
                image_present = True
                checks.append(_check("Sandbox image", "pass", image))
            except docker.errors.ImageNotFound:
                checks.append(
                    _check(
                        "Sandbox image",
                        "warn",
                        f"{image} is not downloaded",
                        fix="Run a scan to pull it automatically.",
                    )
                )
    except Exception as exc:
        client = None
        checks.append(
            _check(
                "Docker daemon",
                "fail",
                str(exc),
                fix=_docker_connection_fix(env),
            )
        )

    if check_network:
        if client is None or settings is None or not image_present:
            checks.append(
                _check(
                    "Container HTTPS",
                    "warn",
                    "skipped because Docker or the sandbox image is unavailable",
                )
            )
        else:
            try:
                output = client.containers.run(
                    str(settings.runtime.image),
                    command=["-sSI", "--max-time", "15", "https://ghcr.io/v2/"],
                    entrypoint="curl",
                    remove=True,
                )
                raw_output = output if isinstance(output, bytes) else str(output).encode()
                first_line = raw_output.decode("utf-8", errors="replace").splitlines()[0]
                checks.append(_check("Container HTTPS", "pass", first_line))
            except Exception as exc:
                checks.append(
                    _check(
                        "Container HTTPS",
                        "fail",
                        str(exc),
                        fix=(
                            "The Docker daemon works but container egress does not. Check VPN "
                            "local-network/firewall rules, Docker DNS, and stale proxy variables."
                        ),
                    )
                )

    if client is not None:
        with contextlib.suppress(Exception):
            client.close()

    return {
        "ok": not any(check["status"] == "fail" for check in checks),
        "platform": platform.platform(),
        "wsl": _is_wsl(),
        "checks": checks,
    }


def _print_human(report: dict[str, Any]) -> None:
    styles = {
        "pass": ("PASS", "bold green"),
        "warn": ("WARN", "bold yellow"),
        "fail": ("FAIL", "bold red"),
    }
    body = Text()
    body.append(f"Platform  {report['platform']}\n", style="dim")
    for check in report["checks"]:
        label, style = styles[check["status"]]
        body.append(f"\n[{label}] ", style=style)
        body.append(f"{check['name']}: ", style="bold white")
        body.append(str(check["detail"]), style="white")
        if check.get("fix"):
            body.append(f"\n       {check['fix']}", style="dim yellow")
    body.append("\n\n")
    if report["ok"]:
        body.append("Runtime checks passed", style="bold green")
    else:
        body.append("Fix the failed checks before starting a local scan", style="bold red")
    Console().print(
        Panel(
            body,
            title="[bold white]STRIX DOCTOR",
            title_align="left",
            border_style="green" if report["ok"] else "red",
            padding=(1, 2),
        )
    )


def run_doctor(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="strix doctor",
        description=(
            "Check the Strix installation, Docker runtime, model config, and VPN/proxy path."
        ),
    )
    parser.add_argument(
        "--network",
        action="store_true",
        help="Also launch a disposable sandbox container and test outbound HTTPS.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args(argv)
    report = collect_diagnostics(check_network=args.network)
    if args.json:
        sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    else:
        _print_human(report)
    return 0 if report["ok"] else 1
