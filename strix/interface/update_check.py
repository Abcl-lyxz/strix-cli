"""Update notifications and self-update for the strix CLI.

Follows the pattern used by tools like gh, uv, and pip: a background,
rate-limited (once per 24h) check against the release source, a cached
result in ``~/.strix``, a non-intrusive notice with the upgrade command
for the detected install method, and a ``strix --update`` self-update
path for the standalone binary install.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import cast

import requests
from rich.console import Console
from rich.prompt import Prompt

from strix.notifications import NotificationAction, notify
from strix.report.state import get_global_report_state
from strix.telemetry._common import get_version
from strix.utils.atomic import atomic_write_text


logger = logging.getLogger(__name__)

GITHUB_REPO = "Abcl-lyxz/strix-cli"
RELEASE_MANIFEST_NAME = "release-manifest.json"
CHECK_INTERVAL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT_SECONDS = 5

_CACHE_PATH = Path.home() / ".strix" / "update-check.json"

_background_thread: threading.Thread | None = None


def _object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return cast("dict[str, object]", value)


def _source_checkout_root() -> Path | None:
    """Return the repository root when this module is running from a checkout."""
    candidate = Path(__file__).resolve().parents[2]
    return (
        candidate
        if (candidate / ".git").exists() and (candidate / "pyproject.toml").is_file()
        else None
    )


def _active_scan() -> bool:
    with contextlib.suppress(Exception):
        report = get_global_report_state()
        return bool(report is not None and report.run_record.get("status") == "running")
    return False


def _is_disabled() -> bool:
    return bool(os.environ.get("STRIX_NO_UPDATE_CHECK")) or any(
        os.environ.get(key)
        for key in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI")
    )


def is_binary_install() -> bool:
    return bool(getattr(sys, "frozen", False))


def get_install_method() -> str:
    if is_binary_install():
        return "binary"
    prefix = str(Path(sys.prefix)).replace("\\", "/")
    if "/pipx/" in prefix or prefix.endswith("/pipx"):
        return "pipx"
    if "/uv/tools/" in prefix:
        return "uv"
    if _source_checkout_root() is not None:
        return "source"
    return "pip"


def get_upgrade_command(method: str | None = None) -> str:
    """Keep every install method on this distribution's verified releases."""
    del method
    return "strix --update"


def _parse_version(value: str) -> tuple[int, ...] | None:
    parts = value.strip().lstrip("v").split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def _is_newer(latest: str, current: str) -> bool:
    latest_parts = _parse_version(latest)
    current_parts = _parse_version(current)
    if latest_parts is None or current_parts is None:
        return False
    return latest_parts > current_parts


def _fetch_latest_version() -> str | None:
    try:
        with requests.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as response:
            response.raise_for_status()
            tag = _object_dict(cast("object", response.json())).get("tag_name", "")
        if not isinstance(tag, str) or _parse_version(tag) is None:
            return None
        return tag.lstrip("v")
    except Exception:  # noqa: BLE001
        logger.debug("update check failed", exc_info=True)
        return None


def _fetch_release(version: str) -> dict[str, object]:
    with requests.get(
        f"https://api.github.com/repos/{GITHUB_REPO}/releases/tags/v{version}",
        timeout=REQUEST_TIMEOUT_SECONDS,
    ) as response:
        response.raise_for_status()
        data = cast("object", response.json())
    if not isinstance(data, dict):
        raise TypeError("GitHub returned an invalid release record")
    return _object_dict(cast("object", data))


def _validate_release_manifest(version: str, manifest: dict[str, object]) -> None:
    if manifest.get("version") != version:
        raise RuntimeError("release manifest version does not match the tag")
    commit = manifest.get("release_commit")
    if not (
        isinstance(commit, str)
        and len(commit) == 40
        and all(character in "0123456789abcdef" for character in commit.lower())
    ):
        raise TypeError("release manifest has no valid release commit")
    if manifest.get("schema_version") != 1:
        raise TypeError("release manifest uses an unsupported schema")
    supported = manifest.get("supported_platforms")
    if not isinstance(supported, list) or not all(
        isinstance(item, str) for item in cast("list[object]", supported)
    ):
        raise TypeError("release manifest has no supported platform list")
    provenance = manifest.get("provenance")
    expected_repository = f"https://github.com/{GITHUB_REPO}"
    if (
        not isinstance(provenance, dict)
        or _object_dict(cast("object", provenance)).get("repository") != expected_repository
    ):
        raise TypeError("release manifest provenance does not match this distribution")
    manifest_assets = manifest.get("assets")
    if not isinstance(manifest_assets, dict) or not manifest_assets:
        raise TypeError("release manifest has no assets")
    for record in _object_dict(cast("object", manifest_assets)).values():
        checksum = (
            _object_dict(cast("object", record)).get("sha256") if isinstance(record, dict) else None
        )
        valid_checksum = (
            isinstance(checksum, str)
            and len(checksum) == 64
            and all(character in "0123456789abcdef" for character in checksum.lower())
        )
        if not valid_checksum:
            raise TypeError("release manifest contains an invalid asset record")


def _fetch_release_manifest(version: str) -> dict[str, object]:
    """Download a manifest whose own digest is attested by GitHub Releases."""
    try:
        release = _fetch_release(version)
        assets = release.get("assets", [])
        if not isinstance(assets, list):
            raise TypeError("GitHub release has no asset list")
        for asset_value in cast("list[object]", assets):
            if not isinstance(asset_value, dict):
                continue
            asset = _object_dict(cast("object", asset_value))
            if asset.get("name") != RELEASE_MANIFEST_NAME:
                continue
            digest = str(asset.get("digest") or "")
            url = str(asset.get("browser_download_url") or "")
            if not digest.startswith("sha256:") or not url:
                raise RuntimeError("release manifest has no GitHub-attested SHA-256 digest")
            with requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                response.raise_for_status()
                raw = response.content
            if hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
                raise RuntimeError("release manifest checksum mismatch")
            manifest = cast("object", json.loads(raw))
            if not isinstance(manifest, dict):
                raise TypeError("release manifest must be an object")
            typed_manifest = _object_dict(cast("object", manifest))
            _validate_release_manifest(version, typed_manifest)
            return typed_manifest
        raise RuntimeError("release has no integrity manifest")
    except (requests.RequestException, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot verify release manifest: {exc}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_cache() -> dict[str, object]:
    try:
        with _CACHE_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return cast("dict[str, object]", data)
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110
    return {}


def _write_cache(**fields: object) -> None:
    try:
        cache = _read_cache()
        cache.update(fields)
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110


def skip_version(version: str) -> None:
    """Remember not to prompt again for this version (newer releases still notify)."""
    _write_cache(skipped_version=version)


def _refresh_cache() -> None:
    latest = _fetch_latest_version()
    if latest:
        notes = ""
        with contextlib.suppress(Exception):
            notes = str(_fetch_release(latest).get("body") or "")[:4_000]
        _write_cache(latest_version=latest, checked_at=time.time(), release_notes=notes)
        current = get_version()
        if current != "unknown" and _is_newer(latest, current):
            notify(
                "update.available",
                title=f"Strix {latest} is available",
                detail=notes,
                severity="info",
                dedupe_key=f"update:{latest}",
                actions=(NotificationAction("start_update", "Install update", latest),),
            )


def start_background_check() -> None:
    """Refresh the cached latest-version info in a daemon thread (at most once per 24h)."""
    global _background_thread  # noqa: PLW0603
    if _is_disabled():
        return
    cache = _read_cache()
    checked_at = cache.get("checked_at")
    if isinstance(checked_at, int | float) and time.time() - checked_at < CHECK_INTERVAL_SECONDS:
        return
    _background_thread = threading.Thread(target=_refresh_cache, daemon=True)
    _background_thread.start()


def get_available_update(*, respect_skip: bool = True) -> str | None:
    """Return the newer version from the cache, or None if up to date / unknown."""
    if _is_disabled():
        return None
    if _background_thread is not None:
        _background_thread.join(timeout=0.2)
    cache = _read_cache()
    latest = cache.get("latest_version")
    current = get_version()
    if not isinstance(latest, str) or current == "unknown" or not _is_newer(latest, current):
        return None
    if respect_skip and cache.get("skipped_version") == latest:
        return None
    return latest


def notify_update(console: Console) -> None:
    latest = get_available_update()
    if not latest:
        return
    console.print(
        f"[#eab308]A new version of strix is available:[/] "
        f"[dim]{get_version()}[/] [dim]→[/] [bold #22c55e]{latest}[/]"
        f"  [dim]·[/]  [#60a5fa]{get_upgrade_command()}[/]"
    )
    console.print()


def run_package_upgrade(  # noqa: PLR0911
    console: Console, method: str, *, version: str | None = None
) -> bool:
    """Install only a wheel verified by the matching fork release manifest."""
    latest = version or _fetch_latest_version()
    if not latest:
        console.print("[bold red]Could not determine the latest version for this upgrade.[/]")
        return False
    current = get_version()
    if current != "unknown" and not _is_newer(latest, current):
        console.print(f"[#22c55e]strix {current} is already the latest version.[/]")
        return True
    if method == "source":
        return _update_source_checkout(console, latest)
    try:
        wheel = _download_verified_wheel(latest)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Update failed:[/] {exc}")
        notify(
            "update.failed",
            title="Strix update verification failed",
            detail=str(exc),
            severity="error",
            dedupe_key=f"update-failed:{latest}",
        )
        return False
    commands = {
        "pip": [sys.executable, "-m", "pip", "install", "--upgrade", str(wheel)],
        "pipx": ["pipx", "runpip", "strix-agent", "install", "--upgrade", str(wheel)],
        # ``--force`` reconstructs the complete uv tool environment and leaves
        # a visible partial-install window on Windows. Upgrade only the direct
        # Strix package so already-valid dependencies remain importable.
        "uv": [
            "uv",
            "tool",
            "install",
            "--upgrade-package",
            "strix-agent",
            "--reinstall-package",
            "strix-agent",
            str(wheel),
        ],
    }
    command = commands[method]
    if _needs_package_handoff():
        try:
            _handoff_package_upgrade(console, command, wheel, latest)
        except OSError as exc:
            _cleanup_staged_wheel(wheel)
            console.print(f"[bold red]Could not start the update installer:[/] {exc}")
            return False
        return True
    console.print(f"[dim]Running[/] [#60a5fa]{' '.join(command)}[/]")
    try:
        try:
            result = subprocess.run(command, check=False)  # noqa: S603
        except OSError as e:
            console.print(f"[bold red]Update failed:[/] {e}")
            return False
        if result.returncode != 0:
            console.print(
                f"[bold red]Update failed[/] [dim](exit code {result.returncode}).[/] "
                f"Run it manually: [#60a5fa]{get_upgrade_command(method)}[/]"
            )
            return False
    finally:
        _cleanup_staged_wheel(wheel)
    _write_cache(latest_version=latest, checked_at=time.time())
    console.print("[#22c55e]✓ strix updated — restart the scan to use the new version[/]")
    return True


def _needs_package_handoff() -> bool:
    return sys.platform == "win32"


def _cleanup_staged_wheel(wheel: Path) -> None:
    wheel.unlink(missing_ok=True)
    if wheel.parent.name.startswith("strix-update-"):
        with contextlib.suppress(OSError):
            (wheel.parent / "install.py").unlink(missing_ok=True)
            (wheel.parent / "install.json").unlink(missing_ok=True)
            wheel.parent.rmdir()


def _handoff_package_upgrade(
    console: Console, command: list[str], wheel: Path, version: str
) -> None:
    """Exit before Windows installers replace loaded Python libraries."""
    status = _CACHE_PATH.with_name("update-install.json")
    log = status.with_suffix(".log")
    worker = wheel.parent / "install.py"
    payload = wheel.parent / "install.json"
    started_at = time.time()
    worker.write_bytes(Path(__file__).with_name("update_worker.py").read_bytes())
    payload.write_text(
        json.dumps(
            {
                "parent_pid": os.getpid(),
                "command": command,
                "wheel": str(wheel),
                "sha256": _sha256_file(wheel),
                "version": version,
                "status": str(status),
                "method": command[0],
                "started_at": started_at,
            }
        ),
        encoding="utf-8",
    )
    status.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        status,
        json.dumps({"status": "pending", "version": version, "started_at": started_at}),
    )
    try:
        with log.open("w", encoding="utf-8") as output:
            subprocess.Popen(  # noqa: S603
                [getattr(sys, "_base_executable", sys.executable), "-I", str(worker), str(payload)],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                close_fds=True,
            )
    except OSError:
        status.unlink(missing_ok=True)
        raise
    console.print(
        f"[yellow]Strix {version} is verified and ready to install. "
        "Installation will start when this process exits.[/]"
    )
    console.print(
        "[dim]You can run Strix again now; it will wait for the verified installer if needed.[/]"
    )
    console.print(f"[dim]Installer status: {status}\nInstaller log: {log}[/]", markup=True)


def _package_install_pending(console: Console) -> bool:
    status = _CACHE_PATH.with_name("update-install.json")
    try:
        state = _object_dict(cast("object", json.loads(status.read_text(encoding="utf-8"))))
        started_at = state.get("started_at")
        if (
            state.get("status") in {"pending", "installing", "verifying"}
            and isinstance(started_at, int | float)
            and time.time() - started_at < 1200
        ):
            console.print("[yellow]A verified update is already being installed.[/]")
            console.print(str(status), markup=False)
            return True
        if state.get("status") == "failed":
            console.print("[yellow]The previous installer failed; retrying the update.[/]")
            console.print(str(status.with_suffix(".log")), markup=False)
    except (OSError, ValueError, TypeError):
        pass
    return False


def _download_verified_wheel(version: str) -> Path:
    manifest = _fetch_release_manifest(version)
    raw_assets_value = manifest.get("assets", {})
    if not isinstance(raw_assets_value, dict):
        raise TypeError("release manifest has no assets")
    raw_assets = _object_dict(cast("object", raw_assets_value))
    suffixes = {
        "linux-x86_64": "manylinux_2_17_x86_64.whl",
        "linux-arm64": "manylinux_2_17_aarch64.whl",
        "macos-x86_64": "macosx_11_0_x86_64.whl",
        "macos-arm64": "macosx_11_0_arm64.whl",
        "windows-x86_64": "win_amd64.whl",
    }
    target = _release_target()
    suffix = suffixes.get(target or "")
    filename = next(
        (name for name in raw_assets if suffix and name.endswith(suffix)),
        None,
    )
    if filename is None:
        raise RuntimeError(f"release has no wheel for {target or 'this platform'}")
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise RuntimeError("release contains an invalid wheel filename")
    # Installers parse the distribution, version, and platform from the filename.
    # Keep it intact and isolate concurrent downloads in separate directories.
    directory = Path(tempfile.mkdtemp(prefix="strix-update-"))
    path = directory / filename
    try:
        _download_verified_asset(version, filename, path, manifest=manifest)
    except BaseException:
        path.unlink(missing_ok=True)
        directory.rmdir()
        raise
    return path


def _download_verified_asset(
    version: str,
    filename: str,
    destination: Path,
    *,
    manifest: dict[str, object] | None = None,
) -> None:
    manifest = manifest or _fetch_release_manifest(version)
    assets = _object_dict(manifest.get("assets", {}))
    record = assets.get(filename)
    expected = (
        _object_dict(cast("object", record)).get("sha256") if isinstance(record, dict) else None
    )
    if not isinstance(expected, str) or len(expected) != 64:
        raise RuntimeError(f"release manifest has no checksum for {filename}")
    url = f"https://github.com/{GITHUB_REPO}/releases/download/v{version}/{filename}"
    with requests.get(url, stream=True, timeout=REQUEST_TIMEOUT_SECONDS * 12) as response:  # nosec B113
        response.raise_for_status()
        with destination.open("wb") as output:
            for chunk in response.iter_content(chunk_size=1 << 20):
                output.write(chunk)
    actual = _sha256_file(destination)
    if actual != expected.lower():
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"checksum mismatch for {filename}: expected sha256 {expected}, got {actual}"
        )


def _update_source_checkout(console: Console, version: str) -> bool:
    root = _source_checkout_root()
    if root is None:
        return False
    manifest = _fetch_release_manifest(version)
    commit = str(manifest["release_commit"])

    def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [shutil.which("git") or "git", "-C", str(root), *args],
            check=check,
            capture_output=True,
            text=True,
        )

    try:
        if git("status", "--porcelain").stdout.strip():
            raise RuntimeError(  # noqa: TRY301
                "source checkout is dirty; no files were changed"
            )
        branch = git("branch", "--show-current").stdout.strip()
        if not branch:
            raise RuntimeError("source checkout is detached")  # noqa: TRY301
        upstream = git("rev-parse", "--abbrev-ref", "@{upstream}").stdout.strip()
        if not upstream:
            raise RuntimeError("source branch has no tracking branch")  # noqa: TRY301
        origin = git("remote", "get-url", "origin").stdout.strip().lower()
        if "github.com/abcl-lyxz/strix-cli" not in origin.replace(":", "/"):
            raise RuntimeError(  # noqa: TRY301
                "origin is not the verified Abcl-lyxz/strix-cli release repository"
            )
        git("fetch", "origin", f"refs/tags/v{version}:refs/tags/v{version}")
        tag_commit = git("rev-list", "-n", "1", f"v{version}").stdout.strip()
        if tag_commit != commit:
            raise RuntimeError(  # noqa: TRY301
                "release tag does not match the verified manifest commit"
            )
        git("merge", "--ff-only", commit)
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        notify(
            "update.failed",
            title="Source update needs attention",
            detail=str(exc),
            severity="warning",
            dedupe_key=f"source-update:{root}",
        )
        console.print(f"[bold red]Update failed:[/] {exc}")
        return False
    console.print(f"[#22c55e]✓ Updated source checkout to {version}[/]")
    return True


def prompt_update_if_available(console: Console) -> bool:
    """Offer an interactive update before a scan starts.

    Returns True if strix was updated (caller should re-exec / exit).
    """
    latest = get_available_update()
    if not latest or not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    console.print()
    console.print(
        f"[#eab308]A new version of strix is available:[/] "
        f"[dim]{get_version()}[/] [dim]→[/] [bold #22c55e]{latest}[/]"
    )
    notes = _read_cache().get("release_notes")
    if isinstance(notes, str) and notes.strip():
        console.print(notes.strip(), style="dim", markup=False)
    console.print(
        "[dim]  y — update now    n — not now (ask again next run)    s — skip this version[/]"
    )
    choice = Prompt.ask("Update strix?", choices=["y", "n", "s"], default="n")
    console.print()
    if choice == "s":
        skip_version(latest)
        return False
    if choice != "y":
        return False
    return self_update(console, version=latest)


def restart_env() -> dict[str, str]:
    """Environment for re-exec'ing the binary after a self-update.

    The PyInstaller bootloader marks its child process via environment
    variables (``_MEIPASS2`` on older versions, ``_PYI_*`` on 6.x) that
    point at the already-extracted archive of the *running* version. If
    they leak into the re-exec'd process, the new binary skips extraction
    and runs the old code, so the update never appears to take effect.
    Library-path variables the bootloader overrode are restored from the
    ``*_ORIG`` copies it saved.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key != "_MEIPASS2" and not key.startswith("_PYI_")
    }
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
        orig = env.pop(f"{var}_ORIG", None)
        if orig is not None:
            env[var] = orig
        elif var in os.environ:
            env.pop(var, None)
    return env


def restart_after_update() -> None:
    """Replace the current process with the freshly updated binary."""
    os.execve(sys.executable, sys.argv, restart_env())  # noqa: S606  # nosec B606


def _release_target() -> str | None:
    raw_os = platform.system().lower()
    os_name = {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(raw_os)
    arch = platform.machine().lower()
    arch = {"aarch64": "arm64", "amd64": "x86_64"}.get(arch, arch)
    if os_name is None:
        return None
    target = f"{os_name}-{arch}"
    supported = {
        "linux-x86_64",
        "linux-arm64",
        "macos-x86_64",
        "macos-arm64",
        "windows-x86_64",
    }
    return target if target in supported else None


def _download_and_replace(version: str, target: str, console: Console) -> bool:
    is_windows = target.startswith("windows")
    archive_ext = ".zip" if is_windows else ".tar.gz"
    filename = f"strix-{version}-{target}{archive_ext}"
    binary_name = f"strix-{version}-{target}" + (".exe" if is_windows else "")
    current_exe = Path(sys.executable).resolve()
    manifest = _fetch_release_manifest(version)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        archive_path = tmp_dir / filename
        console.print(f"[dim]Downloading and verifying[/] {filename}")
        _download_verified_asset(version, filename, archive_path, manifest=manifest)

        if is_windows:
            with zipfile.ZipFile(archive_path) as zf:
                zf.extract(binary_name, tmp_dir)
        else:
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extract(binary_name, tmp_dir, filter="data")

        new_binary = tmp_dir / binary_name
        if not new_binary.is_file():
            raise RuntimeError(f"release archive does not contain {binary_name}")
        new_binary.chmod(new_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        smoke = subprocess.run(  # noqa: S603
            [str(new_binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if smoke.returncode != 0 or version not in f"{smoke.stdout}\n{smoke.stderr}":
            raise RuntimeError("staged binary failed its version smoke test")

        staged = current_exe.with_name(current_exe.name + ".new")
        try:
            shutil.copy2(new_binary, staged)
            _atomic_replace_with_rollback(current_exe, staged)
        except Exception:
            staged.unlink(missing_ok=True)
            raise
    return True


def _atomic_replace_with_rollback(current: Path, staged: Path) -> Path:
    """Install ``staged`` and preserve exactly one recoverable prior binary."""
    rollback = current.with_name(current.name + ".old")
    rollback.unlink(missing_ok=True)
    current.replace(rollback)
    try:
        staged.replace(current)
    except Exception:
        rollback.replace(current)
        raise
    return rollback


def self_update(  # noqa: PLR0911
    console: Console | None = None, version: str | None = None
) -> bool:
    """Replace the running standalone binary with the latest release.

    Returns True on success, accepted Windows handoff, or when already current.
    Package installs use the same verified release source as binary installs.
    """
    console = console or Console()

    if _active_scan():
        console.print("[yellow]An update cannot be installed during an active scan.[/]")
        notify(
            "update.failed",
            title="Update postponed until the scan finishes",
            severity="warning",
            dedupe_key="update-active-scan",
        )
        return False

    if not is_binary_install():
        if _package_install_pending(console):
            return True
        method = get_install_method()
        return run_package_upgrade(console, method, version=version)

    latest = version or _fetch_latest_version()
    if not latest:
        console.print("[bold red]Could not determine the latest strix version.[/]")
        return False

    current = get_version()
    if current != "unknown" and not _is_newer(latest, current):
        console.print(f"[#22c55e]strix {current} is already the latest version.[/]")
        return True

    target = _release_target()
    if not target:
        console.print(
            f"[bold red]No prebuilt binary for this platform "
            f"({platform.system()}/{platform.machine()}).[/]"
        )
        return False

    try:
        _download_and_replace(latest, target, console)
    except Exception as e:  # noqa: BLE001
        logger.debug("self-update failed", exc_info=True)
        console.print(f"[bold red]Update failed:[/] {e}")
        console.print(
            "[dim]Download this distribution's release from:[/] "
            f"[#60a5fa]https://github.com/{GITHUB_REPO}/releases/latest[/]"
        )
        notify(
            "update.failed",
            title="Strix update failed",
            detail=str(e),
            severity="error",
            dedupe_key=f"update-failed:{latest}",
        )
        return False

    _write_cache(latest_version=latest, checked_at=time.time())
    console.print(f"[#22c55e]✓ Updated strix to {latest}[/]")
    return True
