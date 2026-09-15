"""Capability catalog and supervised long-running security jobs."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import ipaddress
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from agents import RunContextWrapper, function_tool

from strix.config import load_settings
from strix.core.paths import run_dir_for
from strix.llm.error_envelope import error_envelope
from strix.utils.secret_files import write_secret_text


SafetyClass = Literal["read-only", "active", "privileged", "device-required"]


_CAPABILITIES: dict[str, dict[str, Any]] = {
    "http-enumeration": {
        "pack": "core",
        "programs": ["httpx", "katana", "ffuf"],
        "safety": "active",
    },
    "web-vulnerability-scan": {
        "pack": "core",
        "programs": ["nuclei", "wapiti"],
        "safety": "active",
    },
    "source-analysis": {
        "pack": "core",
        "programs": ["semgrep", "bandit", "trivy"],
        "safety": "read-only",
    },
    "network-discovery": {
        "pack": "network",
        "programs": ["nmap", "naabu", "masscan"],
        "safety": "active",
    },
    "packet-capture": {
        "pack": "network",
        "programs": ["tcpdump", "tshark"],
        "safety": "privileged",
    },
    "wired-l2-discovery": {
        "pack": "network",
        "programs": ["arp-scan", "netdiscover"],
        "safety": "privileged",
    },
    "dns-assessment": {"pack": "network", "programs": ["dig", "dnsrecon"], "safety": "active"},
    "snmp-assessment": {
        "pack": "network",
        "programs": ["snmpwalk", "onesixtyone"],
        "safety": "active",
    },
    "tls-assessment": {"pack": "network", "programs": ["sslscan", "testssl"], "safety": "active"},
    "windows-service-assessment": {
        "pack": "identity",
        "programs": ["netexec", "enum4linux-ng", "smbclient"],
        "safety": "active",
    },
    "identity-protocol-assessment": {
        "pack": "identity",
        "programs": ["ldapsearch", "kerbrute", "impacket-GetUserSPNs"],
        "safety": "active",
    },
    "ad-graph-collection": {
        "pack": "identity",
        "programs": ["bloodhound-python"],
        "safety": "active",
    },
    "cloud-posture": {
        "pack": "cloud",
        "programs": ["prowler", "scout", "trivy"],
        "safety": "read-only",
    },
    "kubernetes-assessment": {
        "pack": "cloud",
        "programs": ["kubectl", "kube-bench", "kube-hunter"],
        "safety": "active",
    },
    "android-static-analysis": {
        "pack": "mobile",
        "programs": ["jadx", "apktool", "apksigner"],
        "safety": "read-only",
    },
    "android-dynamic-analysis": {
        "pack": "mobile",
        "programs": ["adb", "frida-ps"],
        "safety": "device-required",
    },
    "firmware-analysis": {
        "pack": "firmware",
        "programs": ["binwalk", "unsquashfs", "yara"],
        "safety": "read-only",
    },
}


@dataclass(slots=True)
class _Job:
    job_id: str
    capability: str
    program: str
    arguments: list[str]
    safety: SafetyClass
    started_at: float
    task: asyncio.Task[dict[str, Any]]


_jobs: dict[tuple[str, str], _Job] = {}


def _context(ctx: RunContextWrapper) -> tuple[dict[str, Any], Any, str]:
    inner: dict[str, Any] = ctx.context if isinstance(ctx.context, dict) else {}
    session = inner.get("sandbox_session")
    if session is None:
        raise RuntimeError("sandbox session is unavailable")
    scan_id = str(inner.get("scan_id") or "unknown")
    return inner, session, scan_id


def _selected_packs(context: dict[str, Any] | None = None) -> set[str]:
    raw = load_settings().runtime.tool_pack
    if raw == "auto":
        selected = {"core"}
        evidence = json.dumps((context or {}).get("scan_targets", []), default=str).lower()
        if any(marker in evidence for marker in ('"ip"', '"domain"', "cidr", "network")):
            selected.add("network")
        if any(marker in evidence for marker in ("active_directory", "kerberos", "ldap", "smb")):
            selected.add("identity")
        if any(marker in evidence for marker in ("kubernetes", "terraform", "aws", "azure", "gcp")):
            selected.add("cloud")
        if any(marker in evidence for marker in (".apk", "android")):
            selected.add("mobile")
        if any(marker in evidence for marker in ("firmware", ".bin", ".squashfs", ".img")):
            selected.add("firmware")
        return selected
    packs = {item.strip() for item in raw.split(",") if item.strip()}
    unknown = packs - {"core", "network", "identity", "cloud", "mobile", "firmware"}
    if unknown:
        raise ValueError(f"unknown tool pack(s): {', '.join(sorted(unknown))}")
    return packs or {"core"}


@function_tool
async def list_capabilities(ctx: RunContextWrapper, pack: str = "") -> str:
    """List compact scanner capabilities; call describe_capability before use."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    selected = _selected_packs(inner)
    rows = [
        {"name": name, "pack": item["pack"], "safety": item["safety"]}
        for name, item in _CAPABILITIES.items()
        if item["pack"] in selected and (not pack or item["pack"] == pack)
    ]
    return json.dumps({"selected_packs": sorted(selected), "capabilities": rows})


@function_tool
async def describe_capability(ctx: RunContextWrapper, name: str) -> str:
    """Describe the allowed programs and safety requirements for one capability."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    item = _CAPABILITIES.get(name)
    if item is None or item["pack"] not in _selected_packs(inner):
        raise ValueError("unknown capability; call list_capabilities")
    return json.dumps({"name": name, **item})


async def _execute_job(
    session: Any,
    scan_id: str,
    program: str,
    arguments: list[str],
    timeout: int,
) -> dict[str, Any]:
    result = await session.exec(program, *arguments, timeout=timeout)
    stdout = getattr(result, "stdout", b"")
    stderr = getattr(result, "stderr", b"")
    output = stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else str(stdout)
    error = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr)
    digest = hashlib.sha256((output + error).encode()).hexdigest()
    path = f"/workspace/.strix-jobs/{digest}.txt"
    run_artifact = run_dir_for(scan_id) / "artifacts" / "security-jobs" / f"{digest}.txt"
    combined = output + ("\n" + error if error else "")
    await asyncio.to_thread(write_secret_text, run_artifact, combined)
    await session.exec("mkdir", "-p", "/workspace/.strix-jobs", timeout=10)
    await session.write(Path(path), io.BytesIO(combined.encode()))
    return {
        "status": "completed" if result.ok() else "failed",
        "exit_code": getattr(result, "exit_code", None),
        "artifact": path,
        "run_artifact": run_artifact.relative_to(run_dir_for(scan_id)).as_posix(),
        "sha256": digest,
        "preview": (output or error)[:8_000],
    }


@function_tool
async def start_security_job(
    ctx: RunContextWrapper,
    capability: str,
    program: str,
    arguments: list[str] | None = None,
    timeout_seconds: int = 900,
) -> str:
    """Start a supervised scanner job and return immediately with its ID.

    Only programs advertised by describe_capability are accepted. This API is
    for long reads/scans; destructive, denial-of-service, wireless, spraying,
    and lateral-movement operations are not capabilities.
    """
    inner, session, scan_id = _context(ctx)
    item = _CAPABILITIES.get(capability)
    if item is None or item["pack"] not in _selected_packs(inner):
        raise ValueError("capability is unavailable in the selected tool packs")
    if program not in item["programs"]:
        raise ValueError("program is not part of this capability")
    argv = list(arguments or [])
    if len(argv) > 200 or any(not isinstance(arg, str) or "\0" in arg for arg in argv):
        raise ValueError("arguments must be at most 200 NUL-free strings")
    timeout = max(10, min(timeout_seconds, 7_200))
    safety = item["safety"]
    profile = str(inner.get("sandbox_profile") or load_settings().runtime.sandbox_profile)
    if item["pack"] in {"network", "identity"} and profile not in {"network", "lan"}:
        raise ValueError(
            "network and identity scanner jobs require the CIDR-enforced network or lan profile"
        )
    if safety == "privileged" and profile not in {"network", "lan"}:
        raise ValueError("this capability requires the network or lan sandbox profile")
    if capability == "wired-l2-discovery" and profile != "lan":
        raise ValueError("wired L2 discovery requires the explicitly authorized lan profile")
    if capability == "wired-l2-discovery" and "--localnet" in argv:
        raise ValueError("wired L2 discovery requires the explicit authorized CIDR, not --localnet")
    if item["pack"] in {"network", "identity"}:
        scope = str(inner.get("scope_cidr") or load_settings().runtime.scope_cidr or "")
        _validate_network_arguments(argv, scope)
    job_id = uuid4().hex
    task = asyncio.create_task(_execute_job(session, scan_id, program, argv, timeout))
    _jobs[(scan_id, job_id)] = _Job(
        job_id=job_id,
        capability=capability,
        program=program,
        arguments=argv,
        safety=safety,
        started_at=time.time(),
        task=task,
    )
    return json.dumps({"job_id": job_id, "status": "running", "safety": safety})


def _validate_network_arguments(arguments: list[str], raw_scope: str) -> None:
    allowed = [
        ipaddress.ip_network(value.strip(), strict=False)
        for value in raw_scope.split(",")
        if value.strip()
    ]
    for argument in arguments:
        candidate = argument.strip("[](),")
        # Avoid interpreting ordinary numeric values (ports, rates, timeouts)
        # as legacy shorthand IPv4 addresses such as ``0.0.0.80``.
        if "." not in candidate and ":" not in candidate:
            continue
        try:
            requested = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        in_scope = any(
            (
                isinstance(requested, ipaddress.IPv4Network)
                and isinstance(scope, ipaddress.IPv4Network)
                and requested.subnet_of(scope)
            )
            or (
                isinstance(requested, ipaddress.IPv6Network)
                and isinstance(scope, ipaddress.IPv6Network)
                and requested.subnet_of(scope)
            )
            for scope in allowed
        )
        if not in_scope:
            raise ValueError(f"network target {requested} is outside --scope-cidr")


@function_tool
async def read_security_job(ctx: RunContextWrapper, job_id: str) -> str:
    """Read one supervised job's current status and final artifact pointer."""
    _inner, _session, scan_id = _context(ctx)
    job = _jobs.get((scan_id, job_id))
    if job is None:
        raise ValueError("unknown security job")
    if not job.task.done():
        return json.dumps(
            {"job_id": job_id, "status": "running", "elapsed_seconds": time.time() - job.started_at}
        )
    if job.task.cancelled():
        return json.dumps({"job_id": job_id, "status": "cancelled"})
    try:
        result = job.task.result()
    except Exception as exc:  # noqa: BLE001 - varied sandbox transports.
        envelope = (
            error_envelope(exc, category_hint="tool_timeout")
            if isinstance(exc, TimeoutError)
            else error_envelope(exc, category_hint="sandbox")
        )
        result = {
            "status": "failed",
            "error": envelope.to_dict(),
        }
    return json.dumps({"job_id": job_id, **result}, ensure_ascii=False)


@function_tool
async def stop_security_job(ctx: RunContextWrapper, job_id: str) -> str:
    """Cancel a running job; active network effects already sent cannot be undone."""
    _inner, _session, scan_id = _context(ctx)
    job = _jobs.get((scan_id, job_id))
    if job is None:
        raise ValueError("unknown security job")
    if not job.task.done():
        job.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await job.task
    return json.dumps(
        {
            "job_id": job_id,
            "status": "cancelled",
            "uncertain_side_effect": job.safety != "read-only",
        }
    )


@function_tool(timeout=30)
async def search_artifacts(ctx: RunContextWrapper, query: str = "") -> str:
    """List content-addressed tool/job artifacts, optionally filtered by name."""
    _inner, session, _scan_id = _context(ctx)
    result = await session.exec(
        "find",
        "/workspace/.tool-output",
        "/workspace/.strix-jobs",
        "-maxdepth",
        "1",
        "-type",
        "f",
        timeout=15,
    )
    stdout = getattr(result, "stdout", b"")
    text = stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else str(stdout)
    paths = [line for line in text.splitlines() if not query or query.lower() in line.lower()]
    return json.dumps({"artifacts": paths[:1_000], "truncated": len(paths) > 1_000})
