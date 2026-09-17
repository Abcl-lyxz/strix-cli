"""Typed interactive setup state and immutable scan snapshots."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ScanDraft:
    """Mutable values owned by the TUI until the user presses Start."""

    targets_info: list[dict[str, Any]] = field(default_factory=list)
    workspace_files: list[dict[str, Any]] = field(default_factory=list)
    instruction: str | None = None
    scan_mode: str = "deep"
    scope_mode: str = "auto"
    diff_base: str | None = None
    max_budget_usd: float | None = None
    max_turns: int = 500
    max_agents: int = 12
    sandbox_profile: str = "web"
    tool_pack: str = "auto"
    workspace_mode: str = "read-only"

    @classmethod
    def from_config(cls, config: Any) -> ScanDraft:
        defaults = config.scan_defaults
        return cls(
            scan_mode=defaults.scan_mode,
            scope_mode=defaults.scope_mode,
            max_budget_usd=defaults.max_budget_usd,
            max_turns=defaults.max_turns,
            max_agents=defaults.max_agents,
            sandbox_profile=defaults.sandbox_profile,
            tool_pack=defaults.tool_pack,
            workspace_mode=defaults.workspace_mode,
        )

    def freeze(self) -> RunConfig:
        return RunConfig(
            targets_info=tuple(deepcopy(self.targets_info)),
            workspace_files=tuple(deepcopy(self.workspace_files)),
            instruction=self.instruction,
            scan_mode=self.scan_mode,
            scope_mode=self.scope_mode,
            diff_base=self.diff_base,
            max_budget_usd=self.max_budget_usd,
            max_turns=self.max_turns,
            max_agents=self.max_agents,
            sandbox_profile=self.sandbox_profile,
            tool_pack=self.tool_pack,
            workspace_mode=self.workspace_mode,
        )


@dataclass(frozen=True, slots=True)
class RunConfig:
    """Immutable configuration captured at the Start boundary."""

    targets_info: tuple[dict[str, Any], ...]
    workspace_files: tuple[dict[str, Any], ...]
    instruction: str | None
    scan_mode: str
    scope_mode: str
    diff_base: str | None
    max_budget_usd: float | None
    max_turns: int
    max_agents: int
    sandbox_profile: str
    tool_pack: str
    workspace_mode: str


@dataclass(slots=True)
class LaunchState:
    """Internal launch envelope; never populated from scan flags."""

    draft: ScanDraft
    needs_setup: bool = True
    non_interactive: bool = False
    run_name: str | None = None
    resume: str | None = None
    target: list[str] = field(default_factory=list)
    target_list: list[str] = field(default_factory=list)
    local_sources: list[dict[str, Any]] = field(default_factory=list)
    diff_scope: dict[str, Any] = field(default_factory=lambda: {"active": False})
    workspace_mount: str | None = None
    workspace_subdir: str | None = None
    user_instruction: str | None = None
    user_explicit_instruction: str | None = None
    scope_cidr: str | None = None
    network_interface: str | None = None
    packet_rate_limit: int | None = None
    sandbox_preflight: Any = True

    @property
    def targets_info(self) -> list[dict[str, Any]]:
        return self.draft.targets_info

    @targets_info.setter
    def targets_info(self, value: list[dict[str, Any]]) -> None:
        self.draft.targets_info = value

    @property
    def workspace_files(self) -> list[dict[str, Any]]:
        return self.draft.workspace_files

    @workspace_files.setter
    def workspace_files(self, value: list[dict[str, Any]]) -> None:
        self.draft.workspace_files = value

    def __getattr__(self, name: str) -> Any:
        draft_fields = ScanDraft.__dataclass_fields__
        if name in draft_fields:
            return getattr(self.draft, name)
        raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name != "draft" and name in ScanDraft.__dataclass_fields__ and hasattr(self, "draft"):
            setattr(self.draft, name, value)
            return
        object.__setattr__(self, name, value)


__all__ = ["LaunchState", "RunConfig", "ScanDraft"]
