"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pydantic import AliasChoices, BaseModel

from strix.config.settings import LlmSettings, Settings
from strix.notifications import notify
from strix.security import SecretStoreUnavailableError, get_secret_store, register_secret
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Mapping

    from pydantic.fields import FieldInfo


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".strix" / "cli-config.json"
_override: Path | None = None
_cached: Settings | None = None
_session_fields: dict[str, dict[str, Any]] = {}

CONFIG_VERSION = 2


def session_fields() -> dict[str, dict[str, Any]]:
    return {section: dict(values) for section, values in _session_fields.items()}


def set_session_field(section: str, name: str, value: Any) -> None:
    global _cached  # noqa: PLW0603
    _session_fields.setdefault(section, {})[name] = value
    _cached = None


# These values are credentials even when their provider accepts them through a
# generic settings field. They are never written back into cli-config.json.
_SECRET_ALIASES = frozenset(
    {
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_EXTRA_HEADERS",
        "DEDUPE_LLM_API_KEY",
        "DEDUPE_LLM_EXTRA_HEADERS",
        "PERPLEXITY_API_KEY",
        "EXA_API_KEY",
        "POSTMAN_API_KEY",
    }
)
_SECRET_CANONICAL = {
    "OPENAI_API_KEY": "LLM_API_KEY",
}

_LINKED_LLM_FIELDS = ("model", "api_key", "api_base")
_PROCESS_ROUTE_ALIASES = frozenset(
    {
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "OLLAMA_API_BASE",
    }
)


def load_settings() -> Settings:
    """Resolve settings from env + JSON file + defaults. Memoized.

    Precedence: env vars win, then the JSON file, then field defaults.
    """
    global _cached  # noqa: PLW0603
    if _cached is None:
        source_path = _override or _DEFAULT_PATH
        init_kwargs: dict[str, Any] = _read_json_overrides(source_path)
        _cached = Settings(**init_kwargs)
        for section, changes in _session_fields.items():
            current = cast("BaseModel", getattr(_cached, section))
            setattr(
                _cached, section, type(current).model_validate({**current.model_dump(), **changes})
            )
        _register_resolved_secrets(_cached)
        logger.debug(
            "load_settings: resolved (override=%s, file_used=%s, json_keys=%d)",
            _override is not None,
            source_path.exists(),
            sum(len(v) for v in init_kwargs.values()),
        )
    return _cached


def config_path() -> Path:
    """Return the active user configuration path."""
    return _override or _DEFAULT_PATH


def read_config_document(path: Path | None = None) -> dict[str, Any]:
    """Read the complete versioned config document without resolving secrets."""
    source = path or config_path()
    if not source.exists():
        return {"version": CONFIG_VERSION, "env": {}, "secret_refs": {}, "routing": {}}
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"version": CONFIG_VERSION, "env": {}, "secret_refs": {}, "routing": {}}
    if not isinstance(data, dict):
        return {"version": CONFIG_VERSION, "env": {}, "secret_refs": {}, "routing": {}}
    result = dict(data)
    result["version"] = CONFIG_VERSION
    for key in ("env", "secret_refs", "routing"):
        if not isinstance(result.get(key), dict):
            result[key] = {}
    return result


def write_config_document(document: Mapping[str, Any], path: Path | None = None) -> None:
    """Atomically persist a config document after enforcing its non-secret shape."""
    global _cached  # noqa: PLW0603
    target = path or config_path()
    payload = dict(document)
    payload["version"] = CONFIG_VERSION
    env_block = payload.get("env")
    if not isinstance(env_block, dict):
        env_block = {}
    plaintext = {str(key).upper() for key in env_block} & _SECRET_ALIASES
    if plaintext:
        raise ValueError(
            "plaintext secrets cannot be written to cli-config.json: "
            + ", ".join(sorted(plaintext))
        )
    payload["env"] = env_block
    target.parent.mkdir(parents=True, exist_ok=True)
    write_secret_text(target, json.dumps(payload, indent=2))
    _cached = None


def apply_config_override(path: Path) -> None:
    """Switch the JSON source to ``path`` and invalidate the cache."""
    global _override, _cached  # noqa: PLW0603
    _override = path
    _cached = None
    _session_fields.clear()
    logger.info("config override applied: %s", path)


def persist_current() -> None:
    """Merge currently-set env vars into the active config file (0o600).

    Values already in the file survive when their env var is unset. Legacy
    model/key/base environment variables are an intentionally process-only
    route and are never written back or allowed to mutate the saved pool.
    """
    s = load_settings()
    target = config_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    document = read_config_document(target)
    _, migration_failures = _migrate_secret_values(document)
    if migration_failures:
        notify(
            "security.credential_migration",
            title="Some saved credentials still need migration",
            detail=(
                "A supported system keychain is required before cli-config.json can be rewritten."
            ),
            severity="warning",
            dedupe_key="credential-migration:cli-config",
        )
        return
    env_block = _document_env(document)
    for sub_name in type(s).model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for finfo in type(sub_model).model_fields.values():
            aliases = [alias.upper() for alias in _aliases_for(finfo)]
            active = next((alias for alias in aliases if alias in os.environ), None)
            if active is None:
                continue
            if active in _PROCESS_ROUTE_ALIASES:
                continue
            for alias in aliases:
                env_block.pop(alias, None)
            if active in _SECRET_ALIASES:
                # Environment credentials are process-only by design.
                continue
            if os.environ[active]:
                env_block[active] = os.environ[active]

    document["env"] = env_block
    write_config_document(document, target)


def persist_overrides(updates: Mapping[str, Any]) -> None:
    """Persist explicit setting overrides and invalidate the settings cache.

    ``updates`` is keyed by environment-style setting aliases (for example
    ``STRIX_LLM`` or ``LLM_API_KEY``).  Every alias for the same field is
    removed before the canonical key is written, so a stale sibling alias can
    never win later.  ``None`` removes a value.  The same secret-file writer as
    :func:`persist_current` keeps credentials private and replaces the file
    atomically.

    This is the write path used by interactive configuration surfaces.  It is
    intentionally limited to aliases declared by :class:`Settings`; callers
    cannot smuggle arbitrary environment variables into the config file.
    """
    if not updates:
        return

    alias_groups = _setting_alias_groups()
    target = config_path()
    document = read_config_document(target)
    _, migration_failures = _migrate_secret_values(document)
    if migration_failures:
        notify(
            "security.credential_migration",
            title="Configuration was not changed",
            detail=(
                "Legacy credentials could not be copied to the system keychain; "
                "the original file was retained."
            ),
            severity="warning",
            dedupe_key="credential-migration:cli-config",
        )
        raise SecretStoreUnavailableError(
            "legacy credentials must be migrated before configuration can be changed"
        )
    env_block = _document_env(document)
    secret_refs = _document_secret_refs(document)
    for requested, value in updates.items():
        key = str(requested).upper()
        aliases = alias_groups.get(key)
        if aliases is None:
            raise ValueError(f"Unsupported persisted setting: {requested}")
        for alias in aliases:
            env_block.pop(alias, None)
            secret_refs.pop(alias, None)
        if key in _SECRET_ALIASES or any(alias in _SECRET_ALIASES for alias in aliases):
            if value is not None:
                canonical = _SECRET_CANONICAL.get(key, key).lower().replace("_", "-")
                ref = f"settings.{canonical}"
                get_secret_store().set(ref, _serialize_secret(value))
                secret_refs[aliases[0]] = ref
        elif value is not None:
            env_block[aliases[0]] = value

    document["env"] = env_block
    document["secret_refs"] = secret_refs
    write_config_document(document, target)


def migrate_legacy_config_secrets() -> dict[str, Any]:
    """Move plaintext credentials from the active config to the OS keychain.

    Each value is written and read back before JSON is redacted. If any write
    fails, that original value remains untouched so migration cannot destroy a
    usable credential.
    """
    document = read_config_document()
    migrated, failed = _migrate_secret_values(document)
    if migrated and not failed:
        write_config_document(document)
    if failed:
        notify(
            "security.credential_migration",
            title="Credential migration needs attention",
            detail=(
                "The original plaintext configuration was retained because keychain "
                "verification failed."
            ),
            severity="warning",
            dedupe_key="credential-migration:cli-config",
        )
    return {"migrated": migrated, "failed": failed, "backend": get_secret_store().backend_name}


def _setting_alias_groups() -> dict[str, tuple[str, ...]]:
    """Map every declared settings alias to its complete sibling group."""
    groups: dict[str, tuple[str, ...]] = {}
    for sub_finfo in Settings.model_fields.values():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        for finfo in sub_cls.model_fields.values():
            aliases = tuple(dict.fromkeys(alias.upper() for alias in _aliases_for(finfo)))
            for alias in aliases:
                groups[alias] = aliases
    return groups


def _register_resolved_secrets(settings: Settings) -> None:
    for sub_name in type(settings).model_fields:
        sub_model = getattr(settings, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for field_name, field_info in type(sub_model).model_fields.items():
            aliases = {alias.upper() for alias in _aliases_for(field_info)}
            if aliases & _SECRET_ALIASES:
                value = getattr(sub_model, field_name)
                if value not in (None, "", {}, []):
                    register_secret(_serialize_secret(value))


def _aliases_for(finfo: FieldInfo) -> list[str]:
    """Collect every env-var name that should populate ``finfo``."""
    aliases: list[str] = []
    if finfo.alias:
        aliases.append(finfo.alias)
    va = finfo.validation_alias
    if isinstance(va, AliasChoices):
        aliases.extend(c for c in va.choices if isinstance(c, str))
    elif isinstance(va, str):
        aliases.append(va)
    return aliases


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    """Read ``{"env": {...}}`` from ``path`` and remap to nested kwargs.

    Only includes keys whose env var is NOT already set, so env always
    wins over the persisted file.
    """
    document = read_config_document(path)
    env_block_upper = _drop_stale_llm_connection(_document_env(document))
    secret_refs = _document_secret_refs(document)
    if not env_block_upper and not secret_refs:
        return {}
    env_present = {k.upper() for k in os.environ}

    nested: dict[str, dict[str, Any]] = {}
    for sub_name, sub_finfo in Settings.model_fields.items():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        sub_data: dict[str, Any] = {}
        for fname, finfo in sub_cls.model_fields.items():
            aliases = [alias.upper() for alias in _aliases_for(finfo)]
            if any(alias in env_present for alias in aliases):
                continue  # env wins under some alias; skip the JSON file for this field
            for alias in aliases:
                if alias in env_block_upper:
                    sub_data[fname] = env_block_upper[alias]
                    break
                if alias in secret_refs:
                    secret = get_secret_store().get(secret_refs[alias])
                    if secret is not None:
                        sub_data[fname] = _deserialize_secret(alias, secret)
                    break
        if sub_data:
            nested[sub_name] = sub_data
    return nested


def _first_alias_value(aliases: list[str], source: Mapping[str, Any]) -> Any | None:
    return next((source[alias] for alias in aliases if alias in source), None)


def _drop_stale_llm_connection(env_block: dict[str, Any]) -> dict[str, Any]:
    """Remove every linked LLM var from ``env_block`` if the shell changed any of them."""
    linked_aliases = [
        [alias.upper() for alias in _aliases_for(LlmSettings.model_fields[name])]
        for name in _LINKED_LLM_FIELDS
    ]
    changed = any(
        (env_value := _first_alias_value(aliases, os.environ)) is not None
        and env_value != _first_alias_value(aliases, env_block)
        for aliases in linked_aliases
    )
    if not changed:
        return env_block
    stale = {alias for aliases in linked_aliases for alias in aliases}
    return {k: v for k, v in env_block.items() if k not in stale}


def _read_env_block(path: Path) -> dict[str, Any]:
    """Return the ``env`` block stored in ``path`` with upper-cased keys, or ``{}``."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    env_block = data.get("env", {}) if isinstance(data, dict) else {}
    if not isinstance(env_block, dict):
        return {}
    return {str(k).upper(): v for k, v in env_block.items()}


def _document_env(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = document.get("env", {})
    if not isinstance(raw, dict):
        return {}
    return {str(key).upper(): value for key, value in raw.items()}


def _document_secret_refs(document: Mapping[str, Any]) -> dict[str, str]:
    raw = document.get("secret_refs", {})
    if not isinstance(raw, dict):
        return {}
    return {
        str(key).upper(): value
        for key, value in raw.items()
        if isinstance(value, str) and value.strip()
    }


def _serialize_secret(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _deserialize_secret(alias: str, value: str) -> Any:
    if alias.endswith("EXTRA_HEADERS"):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value
        return parsed
    return value


def _migrate_secret_values(document: dict[str, Any]) -> tuple[list[str], list[str]]:
    env_block = _document_env(document)
    secret_refs = _document_secret_refs(document)
    migrated: list[str] = []
    failed: list[str] = []
    store = get_secret_store()
    for alias in sorted(env_block.keys() & _SECRET_ALIASES):
        value = env_block[alias]
        if value in (None, ""):
            env_block.pop(alias, None)
            continue
        canonical = _SECRET_CANONICAL.get(alias, alias).lower().replace("_", "-")
        ref = f"settings.{canonical}"
        try:
            store.set(ref, _serialize_secret(value))
        except (SecretStoreUnavailableError, OSError, ValueError):
            failed.append(alias)
            continue
        secret_refs[alias] = ref
        env_block.pop(alias, None)
        migrated.append(alias)
    document["env"] = env_block
    document["secret_refs"] = secret_refs
    return migrated, failed
