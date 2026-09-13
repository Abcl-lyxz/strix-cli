"""Shell completion scripts and candidates for the Strix CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from strix.interface.terminal_text import has_terminal_control, sanitize_terminal_text


_ROOT_COMMANDS = ("auth", "doctor", "view", "routes", "secrets", "notifications", "completions")
_SCAN_FLAGS = (
    "--target",
    "--target-list",
    "--workspace-file",
    "--instruction",
    "--instruction-file",
    "--scan-mode",
    "--resume",
    "--max-budget",
    "--max-turns",
    "--max-agents",
    "--route",
    "--scope",
    "--diff-base",
    "--non-interactive",
    "--help",
    "--version",
)


def run_completions(argv: list[str]) -> int:
    """Print a shell integration script or hidden completion candidates."""
    if argv and argv[0] == "--candidates":
        for candidate in completion_candidates(argv[1:]):
            sys.stdout.write(candidate + "\n")
        return 0
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(
            "Usage: strix completions <zsh|bash|fish>\n\n"
            "Enable tab completion for the current shell:\n"
            "  zsh:  source <(strix completions zsh)\n"
            "  bash: source <(strix completions bash)\n"
            "  fish: strix completions fish | source\n"
        )
        return 0
    shell = argv[0].lower()
    scripts = {"zsh": _zsh_script, "bash": _bash_script, "fish": _fish_script}
    generator = scripts.get(shell)
    if generator is None:
        sys.stderr.write(
            f"Unknown shell: {sanitize_terminal_text(shell)}. Choose zsh, bash, or fish.\n"
        )
        return 2
    sys.stdout.write(generator())
    return 0


def completion_candidates(words: list[str]) -> list[str]:
    """Return candidates for words after the ``strix`` executable."""
    prior, current = _split_cursor(words)
    if prior and prior[-1] in {
        "--target",
        "-t",
        "--target-list",
        "--workspace-file",
        "--instruction-file",
    }:
        candidates = _path_candidates(current)
    elif prior and prior[-1] == "--scan-mode":
        candidates = _matching(("quick", "standard", "deep"), current)
    elif prior[:1] == ["auth"]:
        candidates = _matching(("login", "logout", "status"), current)
    elif prior[:1] == ["view"]:
        candidates = _matching(("--host", "--port", "--no-open", "--help"), current)
    elif prior[:1] == ["cloud"]:
        candidates = []
    else:
        candidates = _matching(
            (*_ROOT_COMMANDS, *_SCAN_FLAGS) if not prior else _SCAN_FLAGS, current
        )
    # The line-oriented shell protocol cannot represent these names safely.
    # Omitting them is preferable to returning a sanitized path that does not exist.
    return [candidate for candidate in candidates if not has_terminal_control(candidate)]


def _split_cursor(words: list[str]) -> tuple[list[str], str]:
    if not words:
        return [], ""
    return words[:-1], words[-1]


def _path_candidates(
    value: str,
    *,
    directories_only: bool = False,
    marker: str = "",
) -> list[str]:
    raw = value.removeprefix(marker) if marker else value
    ends_with_separator = raw.endswith(("/", "\\"))
    expanded = Path(raw or ".").expanduser()
    directory = expanded if ends_with_separator else expanded.parent
    name_prefix = "" if ends_with_separator else expanded.name
    raw_base = raw if ends_with_separator else raw[: len(raw) - len(name_prefix)]
    try:
        entries = directory.iterdir()
        matches = [
            entry
            for entry in entries
            if entry.name.startswith(name_prefix) and (not directories_only or entry.is_dir())
        ]
    except OSError:
        return []

    candidates: list[str] = []
    for entry in sorted(matches, key=lambda item: item.name.casefold()):
        candidate = marker + raw_base + entry.name
        if entry.is_dir():
            candidate += "/"
        candidates.append(candidate)
    return candidates


def _matching(candidates: Any, prefix: str) -> list[str]:
    return sorted({str(candidate) for candidate in candidates if str(candidate).startswith(prefix)})


def _zsh_script() -> str:
    return r"""#compdef strix
_strix() {
  local -a candidates
  candidates=("${(@f)$($words[1] completions --candidates "${words[@]:2}")}")
  _describe 'strix' candidates
}
compdef _strix strix
"""


def _bash_script() -> str:
    return r"""_strix_completion() {
  local -a candidates
  local candidate
  while IFS= read -r candidate; do
    candidates+=("$candidate")
  done < <(strix completions --candidates "${COMP_WORDS[@]:1:$COMP_CWORD}")
  COMPREPLY=("${candidates[@]}")
  for candidate in "${COMPREPLY[@]}"; do
    if [[ $candidate == */ ]]; then
      if type compopt >/dev/null 2>&1; then
        compopt -o nospace
      fi
      break
    fi
  done
}
complete -F _strix_completion strix
"""


def _fish_script() -> str:
    return r"""function __strix_candidates
  set -l words (commandline -opc)
  set -e words[1]
  command strix completions --candidates $words (commandline -ct)
end
complete -c strix -f -a '(__strix_candidates)'
"""
