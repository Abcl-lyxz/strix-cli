"""Extracted interface responsibility module."""

from __future__ import annotations

import os
import sys
from typing import Any

import docker
from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.telemetry import report_error


def check_docker_connection() -> Any:
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as exc:
        report_error("docker_unavailable", exc)
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT AVAILABLE", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Cannot connect to Docker daemon.\n", style="white")
        docker_host = os.environ.get("DOCKER_HOST", "").strip()
        if docker_host.lower().startswith(("tcp://", "http://", "https://")):
            error_text.append(
                "DOCKER_HOST uses a TCP endpoint, which can be blocked when a VPN or firewall "
                "changes routes. Prefer running Strix in the same environment as Docker and "
                "using its local Unix socket or Windows named pipe. If TCP is required, secure "
                "it with TLS.\n",
                style="white",
            )
        elif sys.platform == "win32":
            error_text.append(
                "Start Docker Desktop and verify `docker version`. If Docker runs only inside "
                "WSL, install and run Strix in that same WSL distribution.\n",
                style="white",
            )
        else:
            error_text.append(
                "Start Docker Engine and verify `docker version` as the current user.\n",
                style="white",
            )
        error_text.append("\nRun `strix doctor --network` for a full diagnosis.", style="dim cyan")

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        raise RuntimeError("Docker not available") from None
    else:
        return client


def image_exists(client: Any, image_name: str) -> bool:
    try:
        client.images.get(image_name)
    except ImageNotFound:
        return False
    else:
        return True


def update_layer_status(layers_info: dict[str, str], layer_id: str, layer_status: str) -> None:
    if "Pull complete" in layer_status or "Already exists" in layer_status:
        layers_info[layer_id] = "✓"
    elif "Downloading" in layer_status:
        layers_info[layer_id] = "↓"
    elif "Extracting" in layer_status:
        layers_info[layer_id] = "📦"
    elif "Waiting" in layer_status:
        layers_info[layer_id] = "⏳"
    else:
        layers_info[layer_id] = "•"


def process_pull_line(
    line: dict[str, Any], layers_info: dict[str, str], status: Any, last_update: str
) -> str:
    if "id" in line and "status" in line:
        layer_id = line["id"]
        update_layer_status(layers_info, layer_id, line["status"])

        completed = sum(1 for v in layers_info.values() if v == "✓")
        total = len(layers_info)

        if total > 0:
            update_msg = f"[bold cyan]Progress: {completed}/{total} layers complete"
            if update_msg != last_update:
                status.update(update_msg)
                return update_msg

    elif "status" in line and "id" not in line:
        global_status = line["status"]
        if "Pulling from" in global_status:
            status.update("[bold cyan]Fetching image manifest...")
        elif "Digest:" in global_status:
            status.update("[bold cyan]Verifying image...")
        elif "Status:" in global_status:
            status.update("[bold cyan]Finalizing...")

    return last_update
