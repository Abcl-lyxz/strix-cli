"""Extracted interface responsibility module."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_SUPPORTED_SCOPE_MODES = {"auto", "diff", "full"}
_MAX_FILES_PER_SECTION = 120


@dataclass
class DiffEntry:
    status: str
    path: str
    old_path: str | None = None
    similarity: int | None = None


@dataclass
class RepoDiffScope:
    source_path: str
    workspace_subdir: str | None
    base_ref: str
    merge_base: str
    added_files: list[str]
    modified_files: list[str]
    renamed_files: list[dict[str, Any]]
    deleted_files: list[str]
    analyzable_files: list[str]
    truncated_sections: dict[str, bool] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "workspace_subdir": self.workspace_subdir,
            "base_ref": self.base_ref,
            "merge_base": self.merge_base,
            "added_files": self.added_files,
            "modified_files": self.modified_files,
            "renamed_files": self.renamed_files,
            "deleted_files": self.deleted_files,
            "analyzable_files": self.analyzable_files,
            "added_files_count": len(self.added_files),
            "modified_files_count": len(self.modified_files),
            "renamed_files_count": len(self.renamed_files),
            "deleted_files_count": len(self.deleted_files),
            "analyzable_files_count": len(self.analyzable_files),
            "truncated_sections": self.truncated_sections,
        }


@dataclass
class DiffScopeResult:
    active: bool
    mode: str
    instruction_block: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def _run_git_command(
    repo_path: Path, args: list[str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_path), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=check,
    )


def _run_git_command_raw(
    repo_path: Path, args: list[str], check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_path), *args],  # noqa: S607
        capture_output=True,
        check=check,
    )


def _is_ci_environment(env: dict[str, str]) -> bool:
    return any(
        env.get(key)
        for key in (
            "CI",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "JENKINS_URL",
            "BUILDKITE",
            "CIRCLECI",
        )
    )


def _is_pr_environment(env: dict[str, str]) -> bool:
    return any(
        env.get(key)
        for key in (
            "GITHUB_BASE_REF",
            "GITHUB_HEAD_REF",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
            "GITLAB_MERGE_REQUEST_TARGET_BRANCH_NAME",
            "SYSTEM_PULLREQUEST_TARGETBRANCH",
        )
    )


def _is_git_repo(repo_path: Path) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--is-inside-work-tree"], check=False)
    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def _is_repo_shallow(repo_path: Path) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--is-shallow-repository"], check=False)
    if result.returncode == 0:
        value = result.stdout.strip().lower()
        if value in {"true", "false"}:
            return value == "true"

    git_meta = repo_path / ".git"
    if git_meta.is_dir():
        return (git_meta / "shallow").exists()
    if git_meta.is_file():
        try:
            content = git_meta.read_text(encoding="utf-8").strip()
        except OSError:
            return False
        if content.startswith("gitdir:"):
            git_dir = content.split(":", 1)[1].strip()
            resolved = (repo_path / git_dir).resolve()
            return (resolved / "shallow").exists()
    return False


def _git_ref_exists(repo_path: Path, ref: str) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--verify", "--quiet", ref], check=False)
    return result.returncode == 0


def _resolve_origin_head_ref(repo_path: Path) -> str | None:
    result = _run_git_command(
        repo_path, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], check=False
    )
    if result.returncode != 0:
        return None
    ref = result.stdout.strip()
    return ref or None


def _extract_branch_name(ref: str | None) -> str | None:
    if not ref:
        return None
    value = ref.strip()
    if not value:
        return None
    return value.split("/")[-1]


def _extract_github_base_sha(env: dict[str, str]) -> str | None:
    event_path = env.get("GITHUB_EVENT_PATH", "").strip()
    if not event_path:
        return None

    path = Path(event_path)
    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    base_sha = payload.get("pull_request", {}).get("base", {}).get("sha")
    if isinstance(base_sha, str) and base_sha.strip():
        return base_sha.strip()
    return None


def _resolve_default_branch_name(repo_path: Path, env: dict[str, str]) -> str | None:
    github_base_ref = env.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        return github_base_ref

    origin_head = _resolve_origin_head_ref(repo_path)
    if origin_head:
        branch = _extract_branch_name(origin_head)
        if branch:
            return branch

    if _git_ref_exists(repo_path, "refs/remotes/origin/main"):
        return "main"
    if _git_ref_exists(repo_path, "refs/remotes/origin/master"):
        return "master"

    return None


def _resolve_base_ref(repo_path: Path, diff_base: str | None, env: dict[str, str]) -> str:
    if diff_base and diff_base.strip():
        return diff_base.strip()

    github_base_ref = env.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        github_candidate = f"refs/remotes/origin/{github_base_ref}"
        if _git_ref_exists(repo_path, github_candidate):
            return github_candidate

    github_base_sha = _extract_github_base_sha(env)
    if github_base_sha and _git_ref_exists(repo_path, github_base_sha):
        return github_base_sha

    origin_head = _resolve_origin_head_ref(repo_path)
    if origin_head and _git_ref_exists(repo_path, origin_head):
        return origin_head

    if _git_ref_exists(repo_path, "refs/remotes/origin/main"):
        return "refs/remotes/origin/main"

    if _git_ref_exists(repo_path, "refs/remotes/origin/master"):
        return "refs/remotes/origin/master"

    raise ValueError(
        "Unable to resolve a base ref for diff-scope. Pass --diff-base explicitly "
        "(for example: --diff-base origin/main)."
    )


def _get_current_branch_name(repo_path: Path) -> str | None:
    result = _run_git_command(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
    if result.returncode != 0:
        return None
    branch_name = result.stdout.strip()
    if not branch_name or branch_name == "HEAD":
        return None
    return branch_name


def _parse_name_status_z(raw_output: bytes) -> list[DiffEntry]:
    if not raw_output:
        return []

    tokens = [
        token.decode("utf-8", errors="replace") for token in raw_output.split(b"\x00") if token
    ]
    entries: list[DiffEntry] = []
    index = 0

    while index < len(tokens):
        token = tokens[index]
        status_raw = token
        status_code = status_raw[:1]
        similarity: int | None = None
        if len(status_raw) > 1 and status_raw[1:].isdigit():
            similarity = int(status_raw[1:])

        if status_code in {"R", "C"} and index + 2 < len(tokens):
            old_path = tokens[index + 1]
            new_path = tokens[index + 2]
            entries.append(
                DiffEntry(
                    status=status_code,
                    path=new_path,
                    old_path=old_path,
                    similarity=similarity,
                )
            )
            index += 3
            continue

        if index + 1 < len(tokens):
            path = tokens[index + 1]
            entries.append(DiffEntry(status=status_code, path=path, similarity=similarity))
            index += 2
            continue

        break

    return entries


def _append_unique(container: list[str], seen: set[str], path: str) -> None:
    if path and path not in seen:
        seen.add(path)
        container.append(path)


def _classify_diff_entries(entries: list[DiffEntry]) -> dict[str, Any]:
    added_files: list[str] = []
    modified_files: list[str] = []
    deleted_files: list[str] = []
    renamed_files: list[dict[str, Any]] = []
    analyzable_files: list[str] = []
    analyzable_seen: set[str] = set()
    modified_seen: set[str] = set()

    for entry in entries:
        path = entry.path
        if not path:
            continue

        if entry.status == "D":
            deleted_files.append(path)
            continue

        if entry.status == "A":
            added_files.append(path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        if entry.status == "M":
            _append_unique(modified_files, modified_seen, path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        if entry.status == "R":
            renamed_files.append(
                {
                    "old_path": entry.old_path,
                    "new_path": path,
                    "similarity": entry.similarity,
                }
            )
            _append_unique(analyzable_files, analyzable_seen, path)
            if entry.similarity is None or entry.similarity < 100:
                _append_unique(modified_files, modified_seen, path)
            continue

        if entry.status == "C":
            _append_unique(modified_files, modified_seen, path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        _append_unique(modified_files, modified_seen, path)
        _append_unique(analyzable_files, analyzable_seen, path)

    return {
        "added_files": added_files,
        "modified_files": modified_files,
        "deleted_files": deleted_files,
        "renamed_files": renamed_files,
        "analyzable_files": analyzable_files,
    }


def _truncate_file_list(
    files: list[str], max_files: int = _MAX_FILES_PER_SECTION
) -> tuple[list[str], bool]:
    if len(files) <= max_files:
        return files, False
    return files[:max_files], True


def build_diff_scope_instruction(scopes: list[RepoDiffScope]) -> str:  # noqa: PLR0912
    lines = [
        "The user is requesting a review of a Pull Request.",
        (
            "Instruction: Direct your analysis primarily at the changes in the listed files. "
            "You may reference other files in the repository for context (imports, definitions, "
            "usage), but report findings only if they relate to the listed changes."
        ),
        "For Added files, review the entire file content.",
        "For Modified files, focus primarily on the changed areas.",
    ]

    for scope in scopes:
        repo_name = scope.workspace_subdir or Path(scope.source_path).name or "repository"
        lines.append("")
        lines.append(f"Repository Scope: {repo_name}")
        lines.append(f"Base reference: {scope.base_ref}")
        lines.append(f"Merge base: {scope.merge_base}")

        focus_files, focus_truncated = _truncate_file_list(scope.analyzable_files)
        scope.truncated_sections["analyzable_files"] = focus_truncated
        if focus_files:
            lines.append("Primary Focus (changed files to analyze):")
            lines.extend(f"- {path}" for path in focus_files)
            if focus_truncated:
                lines.append(f"- ... ({len(scope.analyzable_files) - len(focus_files)} more files)")
        else:
            lines.append("Primary Focus: No analyzable changed files detected.")

        added_files, added_truncated = _truncate_file_list(scope.added_files)
        scope.truncated_sections["added_files"] = added_truncated
        if added_files:
            lines.append("Added files (review entire file):")
            lines.extend(f"- {path}" for path in added_files)
            if added_truncated:
                lines.append(f"- ... ({len(scope.added_files) - len(added_files)} more files)")

        modified_files, modified_truncated = _truncate_file_list(scope.modified_files)
        scope.truncated_sections["modified_files"] = modified_truncated
        if modified_files:
            lines.append("Modified files (focus on changes):")
            lines.extend(f"- {path}" for path in modified_files)
            if modified_truncated:
                lines.append(
                    f"- ... ({len(scope.modified_files) - len(modified_files)} more files)"
                )

        if scope.renamed_files:
            rename_lines = []
            for rename in scope.renamed_files:
                old_path = rename.get("old_path") or "unknown"
                new_path = rename.get("new_path") or "unknown"
                similarity = rename.get("similarity")
                if isinstance(similarity, int):
                    rename_lines.append(f"- {old_path} -> {new_path} (similarity {similarity}%)")
                else:
                    rename_lines.append(f"- {old_path} -> {new_path}")
            lines.append("Renamed files:")
            lines.extend(rename_lines)

        deleted_files, deleted_truncated = _truncate_file_list(scope.deleted_files)
        scope.truncated_sections["deleted_files"] = deleted_truncated
        if deleted_files:
            lines.append("Note: These files were deleted (context only, not analyzable):")
            lines.extend(f"- {path}" for path in deleted_files)
            if deleted_truncated:
                lines.append(f"- ... ({len(scope.deleted_files) - len(deleted_files)} more files)")

    return "\n".join(lines).strip()


def _should_activate_auto_scope(
    local_sources: list[dict[str, str]], non_interactive: bool, env: dict[str, str]
) -> bool:
    if not local_sources:
        return False
    if not non_interactive:
        return False
    if not _is_ci_environment(env):
        return False
    if _is_pr_environment(env):
        return True

    for source in local_sources:
        source_path = source.get("source_path")
        if not source_path:
            continue
        repo_path = Path(source_path)
        if not _is_git_repo(repo_path):
            continue
        current_branch = _get_current_branch_name(repo_path)
        default_branch = _resolve_default_branch_name(repo_path, env)
        if current_branch and default_branch and current_branch != default_branch:
            return True
    return False


def _resolve_repo_diff_scope(
    source: dict[str, str], diff_base: str | None, env: dict[str, str]
) -> RepoDiffScope:
    source_path = source.get("source_path", "")
    workspace_subdir = source.get("workspace_subdir")
    repo_path = Path(source_path)

    if not _is_git_repo(repo_path):
        raise ValueError(f"Source is not a git repository: {source_path}")

    if _is_repo_shallow(repo_path):
        raise ValueError(
            "Strix requires full git history for diff-scope. Please set fetch-depth: 0 "
            "in your CI config."
        )

    base_ref = _resolve_base_ref(repo_path, diff_base, env)
    merge_base_result = _run_git_command(repo_path, ["merge-base", base_ref, "HEAD"], check=False)
    if merge_base_result.returncode != 0:
        stderr = merge_base_result.stderr.strip()
        raise ValueError(
            f"Unable to compute merge-base against '{base_ref}' for '{source_path}'. "
            f"{stderr or 'Ensure the base branch history is fetched and reachable.'}"
        )

    merge_base = merge_base_result.stdout.strip()
    if not merge_base:
        raise ValueError(
            f"Unable to compute merge-base against '{base_ref}' for '{source_path}'. "
            "Ensure the base branch history is fetched and reachable."
        )

    diff_result = _run_git_command_raw(
        repo_path,
        [
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--find-copies",
            f"{merge_base}...HEAD",
        ],
        check=False,
    )
    if diff_result.returncode != 0:
        stderr = diff_result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"Unable to resolve changed files for '{source_path}'. "
            f"{stderr or 'Ensure the repository has enough history for diff-scope.'}"
        )

    entries = _parse_name_status_z(diff_result.stdout)
    classified = _classify_diff_entries(entries)

    return RepoDiffScope(
        source_path=source_path,
        workspace_subdir=workspace_subdir,
        base_ref=base_ref,
        merge_base=merge_base,
        added_files=classified["added_files"],
        modified_files=classified["modified_files"],
        renamed_files=classified["renamed_files"],
        deleted_files=classified["deleted_files"],
        analyzable_files=classified["analyzable_files"],
    )


def resolve_diff_scope_context(  # noqa: PLR0912
    local_sources: list[dict[str, str]],
    scope_mode: str,
    diff_base: str | None,
    non_interactive: bool,
    env: dict[str, str] | None = None,
) -> DiffScopeResult:
    if scope_mode not in _SUPPORTED_SCOPE_MODES:
        raise ValueError(f"Unsupported scope mode: {scope_mode}")

    env_map = dict(os.environ if env is None else env)

    if scope_mode == "full":
        return DiffScopeResult(
            active=False,
            mode=scope_mode,
            metadata={"active": False, "mode": scope_mode},
        )

    if scope_mode == "auto":
        should_activate = _should_activate_auto_scope(local_sources, non_interactive, env_map)
        if not should_activate:
            return DiffScopeResult(
                active=False,
                mode=scope_mode,
                metadata={"active": False, "mode": scope_mode},
            )

    if not local_sources:
        raise ValueError("Diff-scope is active, but no local repository targets were provided.")

    repo_scopes: list[RepoDiffScope] = []
    skipped_non_git: list[str] = []
    skipped_diff_scope: list[str] = []
    for source in local_sources:
        source_path = source.get("source_path")
        if not source_path:
            continue
        if not _is_git_repo(Path(source_path)):
            skipped_non_git.append(source_path)
            continue
        try:
            repo_scopes.append(_resolve_repo_diff_scope(source, diff_base, env_map))
        except ValueError as e:
            if scope_mode == "auto":
                skipped_diff_scope.append(f"{source_path} (diff-scope skipped: {e})")
                continue
            raise

    if not repo_scopes:
        if scope_mode == "auto":
            metadata: dict[str, Any] = {"active": False, "mode": scope_mode}
            if skipped_non_git:
                metadata["skipped_non_git_sources"] = skipped_non_git
            if skipped_diff_scope:
                metadata["skipped_diff_scope_sources"] = skipped_diff_scope
            return DiffScopeResult(active=False, mode=scope_mode, metadata=metadata)

        raise ValueError(
            "Diff-scope is active, but no Git repositories were found. "
            "Use --scope-mode full to disable diff-scope for this run."
        )

    instruction_block = build_diff_scope_instruction(repo_scopes)
    metadata = {
        "active": True,
        "mode": scope_mode,
        "repos": [scope.to_metadata() for scope in repo_scopes],
        "total_repositories": len(repo_scopes),
        "total_analyzable_files": sum(len(scope.analyzable_files) for scope in repo_scopes),
        "total_deleted_files": sum(len(scope.deleted_files) for scope in repo_scopes),
    }
    if skipped_non_git:
        metadata["skipped_non_git_sources"] = skipped_non_git
    if skipped_diff_scope:
        metadata["skipped_diff_scope_sources"] = skipped_diff_scope

    return DiffScopeResult(
        active=True,
        mode=scope_mode,
        instruction_block=instruction_block,
        metadata=metadata,
    )
