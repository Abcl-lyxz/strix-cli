"""Explicit least-privilege sandbox profiles and preflight validation."""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Literal

from strix.config import load_settings


SandboxProfileName = Literal["web", "network", "lan", "remediation"]
_INTERFACE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")


@dataclass(frozen=True, slots=True)
class SandboxProfile:
    name: SandboxProfileName
    cap_add: tuple[str, ...]
    hardened: bool
    read_only_root: bool
    workspace_read_only: bool


def active_profile() -> SandboxProfile:
    settings = load_settings().runtime
    name = settings.sandbox_profile
    profiles = {
        "web": SandboxProfile(
            name="web", cap_add=(), hardened=True, read_only_root=True, workspace_read_only=True
        ),
        "network": SandboxProfile(
            name="network",
            cap_add=("NET_RAW", "NET_ADMIN"),
            hardened=True,
            read_only_root=True,
            workspace_read_only=True,
        ),
        "lan": SandboxProfile(
            name="lan",
            cap_add=("NET_RAW", "NET_ADMIN"),
            hardened=True,
            read_only_root=True,
            workspace_read_only=True,
        ),
        "remediation": SandboxProfile(
            name="remediation",
            cap_add=(),
            hardened=False,
            read_only_root=False,
            workspace_read_only=True,
        ),
    }
    profile = profiles[name]
    if settings.workspace_mode == "read-write" and name != "remediation":
        raise ValueError(
            "A writable workspace requires --sandbox-profile remediation; "
            "raw-network profiles never inherit source write access"
        )
    if settings.workspace_mode == "read-write":
        profile = SandboxProfile(
            name=profile.name,
            cap_add=profile.cap_add,
            hardened=profile.hardened,
            read_only_root=profile.read_only_root,
            workspace_read_only=False,
        )
    return profile


def preflight_profile() -> dict[str, Any]:
    settings = load_settings().runtime
    profile = active_profile()
    scope = settings.scope_cidr
    packs = {value.strip() for value in settings.tool_pack.split(",") if value.strip()}
    allowed_packs = {"auto", "core", "network", "identity", "cloud", "mobile", "firmware"}
    if not packs or packs - allowed_packs or ("auto" in packs and len(packs) > 1):
        raise ValueError(
            "--tool-pack must be auto or a comma-separated subset of "
            "core,network,identity,cloud,mobile,firmware"
        )
    if scope:
        for value in scope.split(","):
            ipaddress.ip_network(value.strip(), strict=False)
    if profile.name in {"network", "lan"} and not scope:
        raise ValueError(f"The {profile.name} profile requires --scope-cidr")
    if profile.name == "lan":
        platform_name: str = sys.platform
        if platform_name != "linux":
            raise ValueError("The lan sandbox profile requires a native Linux Docker host")
        if not settings.lan_acknowledged:
            raise ValueError("The lan profile requires --acknowledge-lan-scope")
        if not scope:
            raise ValueError("The lan profile requires --scope-cidr")
        if settings.packet_rate_limit is None:
            raise ValueError("The lan profile requires --packet-rate-limit")
        interface = settings.network_interface or ""
        if not _INTERFACE.fullmatch(interface):
            raise ValueError("The lan profile requires a valid --network-interface")
        if not os.environ.get("STRIX_DOCKER_SANDBOX_NETWORK", "").strip():
            raise ValueError(
                "The lan profile requires STRIX_DOCKER_SANDBOX_NETWORK naming a preconfigured "
                "macvlan/ipvlan Docker network"
            )
    return {
        "profile": profile.name,
        "cap_add": list(profile.cap_add),
        "cap_drop": ["ALL"] if profile.hardened else [],
        "read_only_root": profile.read_only_root,
        "workspace_mode": "read-only" if profile.workspace_read_only else "read-write",
        "scope_cidr": scope,
        "network_interface": settings.network_interface,
        "packet_rate_limit": settings.packet_rate_limit,
        "tool_pack": settings.tool_pack,
        "platform": sys.platform,
    }


def apply_profile(create_kwargs: dict[str, Any]) -> SandboxProfile:
    """Apply the preflighted Docker controls to container create kwargs."""
    preflight_profile()
    profile = active_profile()
    if profile.hardened:
        create_kwargs["cap_drop"] = ["ALL"]
        create_kwargs["cap_add"] = list(profile.cap_add)
        create_kwargs["security_opt"] = ["no-new-privileges:true"]
        create_kwargs["read_only"] = profile.read_only_root
        create_kwargs["tmpfs"] = {
            "/tmp": "rw,noexec,nosuid,size=512m",  # nosec B108  # noqa: S108
            "/run": "rw,noexec,nosuid,size=64m",
            "/workspace": "rw,nosuid,size=2g",
            "/home/pentester/.cache": "rw,noexec,nosuid,size=512m",
            "/home/pentester/.config": "rw,noexec,nosuid,size=256m",
            "/home/pentester/.local/share": "rw,noexec,nosuid,size=512m",
            "/home/pentester/.pki": "rw,noexec,nosuid,size=64m",
        }
    else:
        create_kwargs["cap_add"] = list(profile.cap_add)
    return profile


__all__ = [
    "SandboxProfile",
    "SandboxProfileName",
    "active_profile",
    "apply_profile",
    "preflight_profile",
]
