import logging
import os
import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import TypeGuard

import yaml

from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)

_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)

_INTERNAL_SKILL_CATEGORIES: frozenset[str] = frozenset({"scan_modes", "coordination", "analysis"})
_ROOT_SKILL_CATEGORY = "root"
_STANDARD_SKILL_CATEGORY = "custom"
_MAX_SKILL_BYTES = 512 * 1024

_EXTRA_SKILL_DIRS: list[Path] = []
_SKILL_METADATA_CACHE: dict[tuple[Path, int, int], dict[str, str]] = {}


def _is_frontmatter_mapping(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def register_skill_dir(path: str | Path) -> None:
    """Add a directory searched for skills ahead of the built-in set.

    The directory uses the same layout as the packaged skills
    (``<root>/<category>/<name>.md``). Skills found in a registered
    directory shadow packaged skills with the same relative path, so
    callers can both add new skills and override existing ones without
    editing the package. The most recently registered directory has the
    highest precedence.
    """
    resolved = Path(path).expanduser().resolve()
    if resolved not in _EXTRA_SKILL_DIRS:
        _EXTRA_SKILL_DIRS.append(resolved)
        logger.info("Registered extra skill dir: %s", resolved)


def registered_skill_dirs() -> tuple[Path, ...]:
    """Return registered extra skill directories, highest precedence first."""
    return tuple(reversed(_EXTRA_SKILL_DIRS))


def skill_search_dirs() -> tuple[Path, ...]:
    """All existing skill roots, highest precedence first (built-in last)."""
    roots = [*registered_skill_dirs(), *_configured_skill_dirs()]
    builtin = get_strix_resource_path("skills")
    roots.append(builtin)
    unique: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            resolved = root.expanduser().resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_dir():
            continue
        seen.add(resolved)
        unique.append(resolved)
    return tuple(unique)


def _configured_skill_dirs() -> tuple[Path, ...]:
    """Discover opt-in and project-local custom skill roots."""
    candidates = [
        Path(value.strip())
        for value in os.environ.get("STRIX_SKILL_DIRS", "").split(os.pathsep)
        if value.strip()
    ]
    working_dir = Path.cwd()
    candidates.extend(
        (
            working_dir / ".strix" / "skills",
            working_dir / ".agents" / "skills",
            working_dir / ".codex" / "skills",
        )
    )
    return tuple(candidates)


def _safe_skill_file(root: Path, candidate: Path) -> Path | None:
    """Resolve a skill file without allowing a symlink to escape its root."""
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file() or not resolved.is_relative_to(resolved_root):
        return None
    return resolved


def _iter_skill_entries_in_root(
    root: Path, *, include_internal: bool = False
) -> Iterator[tuple[str, str, Path]]:
    """Yield legacy markdown and Agent Skills ``SKILL.md`` layouts."""
    try:
        children = sorted(root.iterdir())
    except OSError:
        return
    for file_path in children:
        if (
            file_path.is_file()
            and _is_selectable_root_skill_file(file_path)
            and (safe := _safe_skill_file(root, file_path))
        ):
            yield (_ROOT_SKILL_CATEGORY, file_path.stem, safe)

    for category_dir in children:
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        # Standard Agent Skills layout: <root>/<skill>/SKILL.md.
        if standard := _safe_skill_file(root, category_dir / "SKILL.md"):
            yield (_STANDARD_SKILL_CATEGORY, category_dir.name, standard)
            continue
        if category_dir.name in _INTERNAL_SKILL_CATEGORIES and not include_internal:
            continue
        try:
            category_children = sorted(category_dir.iterdir())
        except OSError:
            continue
        for file_path in category_children:
            if file_path.is_file() and _is_selectable_root_skill_file(file_path):
                if safe := _safe_skill_file(root, file_path):
                    yield (category_dir.name, file_path.stem, safe)
            elif (
                file_path.is_dir()
                and not file_path.name.startswith("__")
                and (standard := _safe_skill_file(root, file_path / "SKILL.md"))
            ):
                yield (category_dir.name, file_path.name, standard)


def _iter_skill_entries(*, include_internal: bool = False) -> Iterator[tuple[str, str, Path]]:
    seen: set[tuple[str, str]] = set()
    for root in skill_search_dirs():
        for category, name, file_path in _iter_skill_entries_in_root(
            root, include_internal=include_internal
        ):
            key = (category, name)
            if key in seen:
                continue
            seen.add(key)
            yield (category, name, file_path)


def _iter_user_skill_files() -> Iterator[tuple[str, str]]:
    """Yield ``(category_name, skill_name)`` for every user-selectable skill."""
    for category, name, _file_path in _iter_skill_entries():
        yield (category, name)


def _is_selectable_root_skill_file(file_path: Path) -> bool:
    return file_path.suffix == ".md" and not (
        file_path.name.startswith("__") or file_path.name == "README.md"
    )


def get_all_skill_names() -> set[str]:
    """Return every user-selectable skill name (bare, no category prefix)."""
    return {name for _, name in _iter_user_skill_files()}


def _get_all_skill_keys() -> set[str]:
    keys: set[str] = set()
    for category, name in _iter_user_skill_files():
        keys.add(f"{category}/{name}")
    return keys


def _get_ambiguous_skill_names() -> set[str]:
    counts = Counter(name for _, name in _iter_user_skill_files())
    return {name for name, count in counts.items() if count > 1}


def _qualified_skill_file_for_name(skill_name: str) -> Path | None:
    category, _, name = skill_name.partition("/")
    for entry_category, entry_name, file_path in _iter_skill_entries(include_internal=True):
        if (entry_category, entry_name) == (category, name):
            return file_path
    return None


def _qualified_skill_files(skill_name: str) -> list[Path]:
    candidate = _qualified_skill_file_for_name(skill_name)
    return [candidate] if candidate is not None else []


def _bare_skill_files(skill_name: str) -> list[Path]:
    return [file_path for _category, name, file_path in _iter_skill_entries() if name == skill_name]


def _parse_skill_content(content: str, source: Path | None = None) -> tuple[dict[str, str], str]:
    """Parse skill frontmatter once and return metadata plus markdown body."""
    frontmatter = _FRONTMATTER_PATTERN.match(content)
    if frontmatter is None:
        return {}, content.lstrip()

    try:
        parsed: object = yaml.safe_load(frontmatter.group("body"))
    except yaml.YAMLError as error:
        logger.warning("Failed to parse skill frontmatter %s: %s", source or "<content>", error)
        parsed = None
    if not _is_frontmatter_mapping(parsed):
        logger.warning("Skill frontmatter is not a mapping: %s", source or "<content>")
        return {}, content[frontmatter.end() :].lstrip()

    metadata = {str(key): "" if value is None else str(value) for key, value in parsed.items()}
    return metadata, content[frontmatter.end() :].lstrip()


def _read_skill_metadata(file_path: Path) -> dict[str, str]:
    try:
        stat = file_path.stat()
    except OSError:
        logger.warning("Skill file disappeared while reading metadata: %s", file_path)
        return {}
    cache_key = (file_path, stat.st_mtime_ns, stat.st_size)
    cached = _SKILL_METADATA_CACHE.get(cache_key)
    if cached is not None:
        return cached
    if stat.st_size > _MAX_SKILL_BYTES:
        logger.warning("Skill file is too large (%d bytes): %s", stat.st_size, file_path)
        return {}
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        logger.warning("Failed to read skill metadata: %s", file_path)
        return {}
    metadata, _ = _parse_skill_content(content, file_path)
    _SKILL_METADATA_CACHE[cache_key] = metadata
    return metadata


def get_available_skills() -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for category, name in _iter_user_skill_files():
        file_path = _qualified_skill_file_for_name(f"{category}/{name}")
        if file_path is None:
            logger.warning(
                "Skill disappeared while gathering available skills: %s/%s",
                category,
                name,
            )
            continue
        metadata = _read_skill_metadata(file_path)
        description = " ".join(metadata.get("description", "").split())
        grouped.setdefault(category, []).append({"name": name, "description": description})
    return grouped


def find_skills(query: str, limit: int = 8) -> list[dict[str, str]]:
    """Rank installed skills by name and frontmatter description."""
    terms = {term for term in re.findall(r"[a-z0-9]+", query.casefold()) if len(term) > 1}
    if not terms or limit <= 0:
        return []
    ranked: list[tuple[int, str, str, str]] = []
    for category, entries in get_available_skills().items():
        for entry in entries:
            name = entry["name"]
            description = entry["description"]
            name_terms = set(re.findall(r"[a-z0-9]+", name.casefold()))
            description_terms = set(re.findall(r"[a-z0-9]+", description.casefold()))
            score = 8 * len(terms & name_terms) + 2 * len(terms & description_terms)
            if query.casefold() in f"{category}/{name}".casefold():
                score += 12
            if score:
                ranked.append((score, category, name, description))
    ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [
        {"name": f"{category}/{name}", "description": description}
        for _score, category, name, description in ranked[:limit]
    ]


def validate_requested_skills(skill_list: list[str], max_skills: int = 5) -> str | None:
    """Validate a list of user-passed skill names.

    Returns ``None`` on success, or a model-readable error message
    describing what was wrong (count exceeded, unknown names).
    """
    if len(skill_list) > max_skills:
        return (
            f"Cannot specify more than {max_skills} skills per agent; "
            f"got {len(skill_list)}. Aim for 1-3 related skills per specialist."
        )
    if not skill_list:
        return None
    available = get_all_skill_names()
    available_keys = _get_all_skill_keys()
    invalid = sorted({s for s in skill_list if s not in available and s not in available_keys})
    if invalid:
        return f"Invalid skill name(s): {invalid}. Available skills: {sorted(available)}"
    ambiguous = sorted({s for s in skill_list if "/" not in s} & _get_ambiguous_skill_names())
    if ambiguous:
        return (
            f"Ambiguous skill name(s): {ambiguous}. Use category-qualified names from: "
            f"{sorted(available_keys)}"
        )
    return None


_LOADED_SKILLS: set[str] = set()


def _track_skill_loaded(skill_name: str, file_path: Path) -> None:
    builtin = get_strix_resource_path("skills")
    if not file_path.is_relative_to(builtin):
        skill_name = "custom"
    _LOADED_SKILLS.add(skill_name)


def get_loaded_skill_names() -> list[str]:
    """Distinct skills loaded so far in this process (custom skills collapse to ``"custom"``)."""
    return sorted(_LOADED_SKILLS)


def _candidate_skill_files(skill_name: str) -> list[Path]:
    """Resolve *skill_name* to effective matching files."""
    if "/" in skill_name:
        return _qualified_skill_files(skill_name)
    return _bare_skill_files(skill_name)


def load_skills(skill_names: list[str]) -> dict[str, str]:
    """Load skill markdown bodies (frontmatter stripped) by name.

    Skill files live at ``strix/skills/<category>/<name>.md`` (or any
    directory added via :func:`register_skill_dir`, searched first).
    Names can be ``"name"`` (any category), ``"category/name"``, or a
    bare file at the skills root. Missing skills are logged and skipped.
    """
    search_dirs = skill_search_dirs()
    if not search_dirs:
        return {}

    skill_content: dict[str, str] = {}
    for skill_name in skill_names:
        candidates = _candidate_skill_files(skill_name)
        if not candidates:
            logger.warning("Skill not found: %s", skill_name)
            continue
        if len(candidates) > 1:
            logger.warning("Ambiguous skill name %s; use a category-qualified name", skill_name)
            continue
        file_path = candidates[0]

        try:
            if file_path.stat().st_size > _MAX_SKILL_BYTES:
                logger.warning("Skill file is too large: %s", file_path)
                continue
            content = file_path.read_text(encoding="utf-8")
        except (OSError, ValueError) as e:
            logger.warning("Failed to load skill %s: %s", skill_name, e)
            continue

        var_name = skill_name.split("/")[-1]
        _, skill_body = _parse_skill_content(content, file_path)
        skill_content[var_name] = skill_body
        logger.debug("Loaded skill: %s -> %s", skill_name, var_name)
        _track_skill_loaded(var_name, file_path)

    logger.debug("load_skills: %d skill(s) resolved", len(skill_content))
    return skill_content
