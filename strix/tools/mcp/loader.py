"""Read the open-source user's MCP servers from ``~/.strix/mcp-servers.json``.

An open-source user lists the MCP servers they want the agent to reach in a
small JSON file. Strix reads it at the start of a run and connects to each
server, holding the live sessions in the run's registry for the agent to reach
on demand. The file is optional; without it the run simply gets no MCP
connections.

Parsing is fail-open. A single malformed entry is logged and skipped rather than
raising, so one bad row never blocks the servers that are valid, and a missing
or unreadable file yields an empty list.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from strix.security import SecretStoreUnavailableError, get_secret_store
from strix.tools.mcp.config import McpConnectionConfig
from strix.utils.secret_files import write_secret_text


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".strix" / "mcp-servers.json"
_PATH_ENV_VAR = "STRIX_MCP_CONFIG"
# Per-run selection, set by the --mcp-server / --mcp-exclude CLI flags. Each is a
# comma-separated list of connection names.
_ONLY_ENV_VAR = "STRIX_MCP_ONLY"
_EXCLUDE_ENV_VAR = "STRIX_MCP_EXCLUDE"


def config_path() -> Path:
    return _resolve_path(None)


def set_session_config(config: McpConnectionConfig) -> None:
    _session_configs[config.name] = config


def _resolve_path(path: Path | None) -> Path:
    if path is not None:
        return path
    override = os.environ.get(_PATH_ENV_VAR)
    if override:
        return Path(override)
    return _DEFAULT_PATH


def _dedupe_by_name(configs: list[McpConnectionConfig]) -> list[McpConnectionConfig]:
    """Keep the first connection of each name, dropping later duplicates.

    A connection's name is its key in the run's registry, so two connections
    sharing a name would collide and the second would overwrite the first. Drop
    the duplicate here, with a warning, instead.
    """
    seen: set[str] = set()
    unique: list[McpConnectionConfig] = []
    for config in configs:
        if config.name in seen:
            logger.warning(
                "Ignoring MCP server %r: another connection already uses that name "
                "(names must be unique because they namespace the server's tools).",
                config.name,
            )
            continue
        seen.add(config.name)
        unique.append(config)
    return unique


def _parse_names(env_var: str) -> set[str]:
    return {name.strip() for name in os.environ.get(env_var, "").split(",") if name.strip()}


def _apply_run_selection(configs: list[McpConnectionConfig]) -> list[McpConnectionConfig]:
    """Restrict this run's connections to an optional include/exclude selection.

    ``STRIX_MCP_ONLY`` (if set) keeps only the named connections; then
    ``STRIX_MCP_EXCLUDE`` drops any named connection. With neither set, every
    connection is kept.
    """
    only = _parse_names(_ONLY_ENV_VAR)
    exclude = _parse_names(_EXCLUDE_ENV_VAR)
    if not only and not exclude:
        return configs

    available = {config.name for config in configs}
    for name in sorted((only | exclude) - available):
        logger.warning(
            "MCP connection selection named %r, which is not configured; ignoring it", name
        )

    selected: list[McpConnectionConfig] = []
    for config in configs:
        if only and config.name not in only:
            continue
        if config.name in exclude:
            continue
        selected.append(config)
    return selected


_session_configs: dict[str, McpConnectionConfig] = {}


def load_user_mcp_configs(path: Path | None = None) -> list[McpConnectionConfig]:
    configs = {c.name: c for c in _load_user_mcp_configs(path)}
    configs.update(_session_configs)
    return list(configs.values())


def _load_user_mcp_configs(path: Path | None = None) -> list[McpConnectionConfig]:
    """Load MCP connection configs from the user's JSON file.

    The path is ``path`` if given, else ``$STRIX_MCP_CONFIG``, else
    ``~/.strix/mcp-servers.json``. The file is a JSON list of server entries.
    A missing file returns ``[]``; an unreadable or non-list file is logged and
    returns ``[]``; individual entries that fail validation are logged and
    skipped. Connections sharing a name are de-duplicated (first wins), and an
    optional per-run include/exclude selection is applied last.
    """
    source = _resolve_path(path)
    if not source.exists():
        return []

    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception("Could not read MCP config at %s; ignoring it", source)
        return []

    if not isinstance(raw, list):
        logger.warning("MCP config at %s is not a JSON list; ignoring it", source)
        return []

    entries = cast("list[object]", raw)
    configs: list[McpConnectionConfig] = []
    sanitized_entries: list[object] = []
    changed = False
    for index, entry in enumerate(entries):
        resolved = entry
        if isinstance(entry, dict):
            resolved, sanitized, migrated = _resolve_auth(entry)
            sanitized_entries.append(sanitized)
            changed = changed or migrated
        else:
            sanitized_entries.append(entry)
        try:
            configs.append(McpConnectionConfig.model_validate(resolved))
        except ValidationError as exc:
            logger.warning("Skipping invalid MCP server entry #%d in %s: %s", index, source, exc)

    if changed:
        try:
            write_secret_text(source, json.dumps(sanitized_entries, indent=2))
        except OSError:
            logger.exception("Could not redact migrated MCP credentials in %s", source)

    return _apply_run_selection(_dedupe_by_name(configs))


def _resolve_auth(entry: dict[str, object]) -> tuple[dict[str, object], dict[str, object], bool]:
    """Resolve a keychain reference and migrate a legacy bearer token safely."""
    resolved = dict(entry)
    sanitized = dict(entry)
    raw_auth = entry.get("auth")
    if not isinstance(raw_auth, dict) or raw_auth.get("kind", "bearer") != "bearer":
        return resolved, sanitized, False
    auth = dict(raw_auth)
    secret_ref = auth.get("secret_ref")
    if isinstance(secret_ref, str):
        try:
            token = get_secret_store().get(secret_ref)
        except (OSError, SecretStoreUnavailableError):
            token = None
        if token:
            auth["token"] = token
            resolved["auth"] = auth
        return resolved, sanitized, False
    token = auth.get("token")
    name = str(entry.get("name") or "server")
    if not isinstance(token, str) or not token:
        return resolved, sanitized, False
    slug = "".join(char if char.isalnum() or char in "._-" else "-" for char in name.lower())
    ref = f"mcp.{slug}.bearer"
    try:
        get_secret_store().set(ref, token)
    except (OSError, SecretStoreUnavailableError, ValueError):
        return resolved, sanitized, False
    clean_auth = {key: value for key, value in auth.items() if key != "token"}
    clean_auth["secret_ref"] = ref
    sanitized["auth"] = clean_auth
    auth["secret_ref"] = ref
    resolved["auth"] = auth
    return resolved, sanitized, True
