"""Extracted interface responsibility module."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests
from rich.console import Console
from yarl import URL

from strix.utils.api_spec import detect_spec_format


def _is_http_git_repo(url: str) -> bool:
    check_url = f"{url.rstrip('/')}/info/refs?service=git-upload-pack"
    try:
        with requests.get(check_url, headers={"User-Agent": "git/2.43.0"}, timeout=10) as resp:
            if resp.status_code >= 400:
                return resp.status_code == 401
            return "x-git-upload-pack-advertisement" in resp.headers.get("Content-Type", "")
    except (requests.RequestException, ValueError):
        return False


def infer_target_type(target: str) -> tuple[str, dict[str, str]]:  # noqa: PLR0911,PLR0912
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")

    target = target.strip().strip("\"'")

    if target.startswith("git@"):
        return "repository", {"target_repo": target}

    if target.startswith("git://"):
        return "repository", {"target_repo": target}

    parsed = urlparse(target)
    if parsed.scheme == "postman":
        collection_uid = f"{parsed.netloc}{parsed.path}".strip("/")
        if not collection_uid:
            raise ValueError(
                f"Missing Postman collection id in '{target}' (expected postman://<collection-uid>)"
            )
        details = {
            "target_spec": target,
            "spec_format": "postman",
            "source": "postman_api",
            "collection_uid": collection_uid,
        }
        query = parse_qs(parsed.query)
        env_uid = (query.get("env") or query.get("environment") or [""])[0].strip()
        if env_uid:
            details["environment_uid"] = env_uid
        return "api_spec", details

    if parsed.scheme in ("http", "https"):
        if parsed.username or parsed.password:
            return "repository", {"target_repo": target}
        if parsed.path.rstrip("/").endswith(".git"):
            return "repository", {"target_repo": target}
        if parsed.query or parsed.fragment:
            return "web_application", {"target_url": target}
        path_segments = [s for s in parsed.path.split("/") if s]
        if len(path_segments) >= 2 and _is_http_git_repo(target):
            return "repository", {"target_repo": target}
        return "web_application", {"target_url": target}

    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return "ip_address", {"target_ip": str(ip_obj)}

    path = Path(target).expanduser()
    try:
        if path.exists():
            if path.is_dir():
                check_mountable_dir(path)
                return "local_code", {"target_path": str(path.resolve())}
            spec_format = detect_spec_format(path)
            if spec_format is not None:
                return "api_spec", {
                    "target_spec": str(path.resolve()),
                    "spec_format": spec_format,
                }
            if path.is_file():
                with path.open("rb"):
                    pass
                return "local_file", {"target_path": str(path.resolve())}
            raise ValueError(f"Path is not a regular file or folder: {target}")
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {target} - {e!s}") from e

    if target.endswith(".git"):
        return "repository", {"target_repo": target}

    if "/" in target:
        host_part, _, path_part = target.partition("/")
        if "." in host_part and not host_part.startswith(".") and path_part:
            full_url = f"https://{target}"
            if _is_http_git_repo(full_url):
                return "repository", {"target_repo": full_url}
            return "web_application", {"target_url": full_url}

    if "." in target and "/" not in target and not target.startswith("."):
        parts = target.split(".")
        if len(parts) >= 2 and all(p and p.strip() for p in parts):
            return "web_application", {"target_url": f"https://{target}"}

    raise ValueError(
        f"Invalid target: {target}\n"
        "Target must be one of:\n"
        "- A valid URL (http:// or https://)\n"
        "- A Git repository URL (https://host/org/repo or git@host:org/repo.git)\n"
        "- A local directory path\n"
        "- An API spec file (OpenAPI/Swagger .json/.yaml or a Postman collection)\n"
        "- A Postman collection by id (postman://<collection-uid>[?env=<environment-uid>], "
        "needs POSTMAN_API_KEY)\n"
        "- A domain name (e.g., example.com)\n"
        "- An IP address (e.g., 192.168.1.10)"
    )


def read_target_list_file(path_str: str) -> list[str]:
    """Read scan targets from a file, one target per non-empty, non-comment line."""
    if not path_str or not path_str.strip():
        raise ValueError("--target-list path must not be empty.")

    path = Path(path_str).expanduser()
    if not path.is_file():
        raise ValueError(f"Target list file '{path_str}' is not an existing file.")

    try:
        targets = [
            target
            for line in path.read_text(encoding="utf-8").splitlines()
            if (target := line.strip()) and not target.startswith("#")
        ]
    except UnicodeDecodeError as e:
        raise ValueError(f"Target list file '{path_str}' must be valid UTF-8 text: {e!s}") from e
    except OSError as e:
        raise ValueError(f"Failed to read target list file '{path_str}': {e!s}") from e

    targets = [target for target in targets if target]
    if not targets:
        raise ValueError(f"Target list file '{path_str}' is empty.")
    return targets


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", name.strip())
    return sanitized or "target"


def derive_repo_base_name(repo_url: str) -> str:
    if repo_url.endswith("/"):
        repo_url = repo_url[:-1]

    if ":" in repo_url and repo_url.startswith("git@"):
        path_part = repo_url.split(":", 1)[1]
    else:
        path_part = urlparse(repo_url).path or repo_url

    candidate = path_part.split("/")[-1]
    if candidate.endswith(".git"):
        candidate = candidate[:-4]

    return sanitize_name(candidate or "repository")


def derive_local_base_name(path_str: str) -> str:
    try:
        base = Path(path_str).resolve().name
    except (OSError, RuntimeError):
        base = Path(path_str).name
    return sanitize_name(base or "workspace")


def assign_workspace_subdirs(targets_info: list[dict[str, Any]]) -> None:
    name_counts: dict[str, int] = {}

    for target in targets_info:
        target_type = target["type"]
        details = target["details"]

        base_name: str | None = None
        if target_type == "repository":
            base_name = derive_repo_base_name(details["target_repo"])
        elif target_type == "local_code":
            base_name = derive_local_base_name(details.get("target_path", "local"))

        if base_name is None:
            continue

        count = name_counts.get(base_name, 0) + 1
        name_counts[base_name] = count

        workspace_subdir = base_name if count == 1 else f"{base_name}-{count}"

        details["workspace_subdir"] = workspace_subdir


def is_whitebox_scan(targets_info: list[dict[str, Any]]) -> bool:
    """True iff any target is a local source tree (whitebox / source-aware)."""
    return any(t.get("type") == "local_code" for t in targets_info or [])


def collect_local_sources(targets_info: list[dict[str, Any]]) -> list[dict[str, Any]]:
    local_sources: list[dict[str, Any]] = []

    for target_info in targets_info:
        details = target_info["details"]
        workspace_subdir = details.get("workspace_subdir")

        if target_info["type"] == "local_code" and "target_path" in details:
            local_sources.append(
                {
                    "source_path": details["target_path"],
                    "workspace_subdir": workspace_subdir,
                    "protect_metadata": True,
                }
            )

        elif target_info["type"] == "repository" and "cloned_repo_path" in details:
            local_sources.append(
                {
                    "source_path": details["cloned_repo_path"],
                    "workspace_subdir": workspace_subdir,
                    "protect_metadata": False,
                }
            )

    return local_sources


# Refused along with everything under them.
_FORBIDDEN_MOUNT_TREES = frozenset(
    {
        "/bin",
        "/sbin",
        "/usr",
        "/etc",
        "/lib",
        "/lib64",
        "/nix/store",
        "/run/current-system/sw",
        "/Applications",
        "/Library",
        "/System",
        "/dev",
        "/boot",
        "/proc",
        "/sys",
    }
)

# Refused themselves, but they hold projects too, so their contents are fine.
_FORBIDDEN_MOUNT_ROOTS = frozenset(
    {
        "/",
        "/private",
        "/var",
        "/opt",
        "/home",
        "/root",
        "/srv",
        "/Users",
        "/Volumes",
    }
)

_FORBIDDEN_WINDOWS_TREE_NAMES = frozenset(
    {"windows", "program files", "program files (x86)", "programdata"}
)

_FORBIDDEN_MOUNT_DIR_NAMES = frozenset(
    {
        ".ssh",
        ".tsh",
        ".brev",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".config",
        ".npm",
        ".pki",
        ".terraform.d",
    }
)


def _is_within(path: Path, ancestor: Path) -> bool:
    ancestor_parts = [part.casefold() for part in ancestor.parts]
    path_parts = [part.casefold() for part in path.parts]
    return path_parts[: len(ancestor_parts)] == ancestor_parts


def check_mountable_dir(path: Path) -> None:
    resolved = path.resolve()
    if not resolved.is_dir():
        raise ValueError(f"'{path}' is not an existing directory.")

    # Both the literal and the resolved form: macOS reaches /etc through the
    # /private/etc symlink, and only the resolved path is compared below.
    exact = {str(Path(root)).casefold() for root in _FORBIDDEN_MOUNT_ROOTS}
    exact |= {str(Path(root).resolve()).casefold() for root in _FORBIDDEN_MOUNT_ROOTS}
    exact.add(str(Path.home().resolve()).casefold())
    tree_roots = set(_FORBIDDEN_MOUNT_TREES)
    if os.name == "nt":
        drive = Path(resolved.anchor)
        tree_roots |= {str(drive / name) for name in _FORBIDDEN_WINDOWS_TREE_NAMES}
        exact.add(str(drive / "Users").casefold())
    trees = [Path(root) for root in tree_roots] + [Path(root).resolve() for root in tree_roots]
    if (
        str(resolved).casefold() in exact
        or resolved.parent == resolved
        or any(_is_within(resolved, tree) for tree in trees)
    ):
        raise ValueError(
            f"Refusing to mount '{resolved}' into the sandbox: it is a system "
            "or home directory, not a codebase. Point the target at the "
            "project directory you want tested."
        )

    credential = next(
        (part for part in resolved.parts if part.casefold() in _FORBIDDEN_MOUNT_DIR_NAMES), None
    )
    if credential is not None:
        raise ValueError(
            f"Refusing to mount '{resolved}' into the sandbox: '{credential}' "
            "holds credentials, not code."
        )


def dedupe_local_targets(targets_info: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for target in targets_info:
        details = target.get("details") or {}
        path = details.get("target_path")
        if target.get("type") != "local_code" or not path:
            result.append(target)
            continue
        if path not in seen_paths:
            seen_paths.add(path)
            result.append(target)
    return result


def _is_localhost_host(host: str) -> bool:
    host_lower = host.lower().strip("[]")

    if host_lower in ("localhost", "0.0.0.0", "::1"):  # nosec B104
        return True

    try:
        ip = ipaddress.ip_address(host_lower)
        if isinstance(ip, ipaddress.IPv4Address):
            return ip.is_loopback  # 127.0.0.0/8
        if isinstance(ip, ipaddress.IPv6Address):
            return ip.is_loopback  # ::1
    except ValueError:
        pass

    return False


def rewrite_localhost_targets(targets_info: list[dict[str, Any]], host_gateway: str) -> None:
    for target_info in targets_info:
        target_type = target_info.get("type")
        details = target_info.get("details", {})

        if target_type == "web_application":
            target_url = details.get("target_url", "")
            try:
                url = URL(target_url)
            except (ValueError, TypeError):
                continue

            if url.host and _is_localhost_host(url.host):
                details["target_url"] = str(url.with_host(host_gateway))

        elif target_type == "ip_address":
            target_ip = details.get("target_ip", "")
            if target_ip and _is_localhost_host(target_ip):
                details["target_ip"] = host_gateway


#: API spec targets are copied into one workspace directory rather than mounted
#: from wherever they happen to live on the host.
API_SPEC_WORKSPACE_SUBDIR = "api-specs"


def write_fetched_collection(collection: dict[str, Any], collection_uid: str) -> str:
    """Write a collection fetched from the Postman API to a local file.

    Returns the file path, so a ``postman://`` target continues as an ordinary
    spec file from here on and the API key never leaves the host.
    """
    staging = Path(tempfile.gettempdir()) / "strix_api_specs" / "fetched"
    staging.mkdir(parents=True, exist_ok=True)
    path = staging / f"{sanitize_name(collection_uid)}.postman_collection.json"
    path.write_text(json.dumps(collection, indent=2), encoding="utf-8")
    return str(path)


def stage_api_specs(targets_info: list[dict[str, Any]], run_name: str) -> list[dict[str, Any]]:
    """Copy every ``api_spec`` target into one directory for the sandbox.

    A spec is a single file the agent reads, not a tree it works in, so it is
    copied to a per-run staging directory that is exposed at
    ``/workspace/api-specs`` instead of mounting its host location. Each target's
    ``workspace_path`` records where the agent will find it.
    """
    specs = [t for t in targets_info if t.get("type") == "api_spec"]
    if not specs:
        return []

    staging = Path(tempfile.gettempdir()) / "strix_api_specs" / run_name
    staging.mkdir(parents=True, exist_ok=True)

    used: set[str] = set()
    for target in specs:
        details = target["details"]
        source = Path(str(details["target_spec"]))
        name = source.name
        stem, suffix = source.stem, source.suffix
        count = 1
        while name in used:
            count += 1
            name = f"{stem}-{count}{suffix}"
        used.add(name)
        shutil.copy2(source, staging / name)
        details["workspace_path"] = f"/workspace/{API_SPEC_WORKSPACE_SUBDIR}/{name}"

    return [
        {
            "source_path": str(staging),
            "workspace_subdir": API_SPEC_WORKSPACE_SUBDIR,
            "protect_metadata": False,
        }
    ]


def clone_repository(repo_url: str, run_name: str, dest_name: str | None = None) -> str:
    console = Console()

    git_executable = shutil.which("git")
    if git_executable is None:
        raise FileNotFoundError("Git executable not found in PATH")

    temp_dir = Path(tempfile.gettempdir()) / "strix_repos" / run_name
    temp_dir.mkdir(parents=True, exist_ok=True)

    if dest_name:
        repo_name = dest_name
    else:
        repo_name = Path(repo_url).stem if repo_url.endswith(".git") else Path(repo_url).name

    clone_path = temp_dir / repo_name

    if clone_path.exists():
        shutil.rmtree(clone_path)

    try:
        with console.status(f"[bold cyan]Cloning repository {repo_url}...", spinner="dots"):
            subprocess.run(  # noqa: S603
                [
                    git_executable,
                    "clone",
                    repo_url,
                    str(clone_path),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

        return str(clone_path.absolute())

    except subprocess.CalledProcessError as e:
        detail = e.stderr if hasattr(e, "stderr") and e.stderr else str(e)
        raise ValueError(f"Could not clone repository {repo_url}: {detail}") from e
    except FileNotFoundError as e:
        raise ValueError(
            "Git is not installed or not available in PATH. "
            "Please install Git to clone repositories."
        ) from e


def validate_config_file(config_path: str) -> Path:
    console = Console()
    path = Path(config_path)

    if not path.exists():
        console.print(f"[bold red]Error:[/] Config file not found: {config_path}")
        sys.exit(1)

    if path.suffix != ".json":
        console.print("[bold red]Error:[/] Config file must be a .json file")
        sys.exit(1)

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/] Invalid JSON in config file: {e}")
        sys.exit(1)

    if not isinstance(data, dict):
        console.print("[bold red]Error:[/] Config file must contain a JSON object")
        sys.exit(1)

    if "env" not in data or not isinstance(data.get("env"), dict):
        console.print("[bold red]Error:[/] Config file must have an 'env' object")
        sys.exit(1)

    return path


# --- Workspace files -------------------------------------------------------
#
# ``--workspace-file`` places a single host file into the sandbox workspace,
# outside every target tree. Content rides the same upload as the target
# sources, so a large file makes session bring-up slower.


def _split_workspace_file_spec(spec: str) -> tuple[str, str | None]:
    """Split ``PATH[:DEST]`` without mistaking a Windows drive for a separator."""
    stripped = spec.strip()
    direct_source = Path(stripped).expanduser()
    if direct_source.is_file():
        return stripped, None

    raw, sep, dest = stripped.rpartition(":")
    if not sep or not dest.strip():
        return stripped, None
    # ``C:\\path`` has one colon, which belongs to the drive designator. A
    # destination-bearing Windows spec has another colon after the path.
    if len(raw) == 1 and raw.isalpha():
        return stripped, None
    return raw.strip(), dest.strip()


def _workspace_file_dest(declared_dest: str | None, source: Path, spec: str) -> str:
    """Return the workspace-relative destination declared by ``spec``."""
    candidate = declared_dest or source.name
    if candidate.startswith("/") or Path(candidate).is_absolute():
        if not candidate.startswith("/workspace/"):
            raise ValueError(
                f"'{spec}' must land inside the workspace: use a relative "
                "destination or a path under /workspace"
            )
        candidate = candidate.removeprefix("/workspace/")
    candidate = candidate.strip("/")
    if not candidate:
        raise ValueError(f"'{spec}' has an empty destination path")
    if any(part in ("", ".", "..") for part in candidate.split("/")):
        raise ValueError(f"'{spec}' has an invalid destination path: {candidate}")
    # A control character would let the path span more than the one line it is
    # rendered on in the agent task, so the whole spec is rejected.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in candidate):
        raise ValueError(f"'{spec}' has a control character in its destination path")
    return candidate


def resolve_workspace_files(specs: list[str] | None) -> list[dict[str, str]]:
    """Validate ``PATH[:DEST]`` specs into source/destination pairs.

    Each spec names a readable host file. ``DEST`` is the path inside
    ``/workspace``; it defaults to the file name. Raises ``ValueError`` with a
    user-facing message when a spec is unusable.
    """
    resolved: list[dict[str, str]] = []
    seen: dict[str, str] = {}
    for spec in specs or []:
        source_text, declared_dest = _split_workspace_file_spec(spec)
        source = Path(source_text.strip()).expanduser()
        if not source.is_file():
            raise ValueError(f"'{source}' is not an existing file")
        try:
            with source.open("rb"):
                pass
        except OSError as error:
            raise ValueError(f"Cannot read '{source}': {error}") from error
        workspace_rel = _workspace_file_dest(declared_dest, source, spec)
        if workspace_rel in seen:
            raise ValueError(
                f"Two workspace files target /workspace/{workspace_rel}: "
                f"'{seen[workspace_rel]}' and '{source}'"
            )
        seen[workspace_rel] = str(source)
        resolved.append(
            {
                "source_path": str(source.resolve()),
                "workspace_path": f"/workspace/{workspace_rel}",
            }
        )
    return resolved


def read_workspace_files(workspace_files: list[dict[str, str]] | None) -> list[dict[str, Any]]:
    """Read resolved workspace files into engine ``extra_files`` entries."""
    entries: list[dict[str, Any]] = []
    for workspace_file in workspace_files or []:
        source = Path(workspace_file["source_path"])
        entries.append(
            {
                "workspace_path": workspace_file["workspace_path"],
                "content": source.read_bytes(),
            }
        )
    return entries
