from pathlib import Path
from typing import Any

from strix.interface.completions import completion_candidates, run_completions


def test_only_local_commands_are_completed() -> None:
    assert completion_candidates(["cl"]) == []
    assert "view" in completion_candidates([""])
    assert "routes" in completion_candidates([""])
    assert completion_candidates(["--scan-mode", "q"]) == ["quick"]


def test_file_completion_keeps_spaces(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "source tree").mkdir()
    assert completion_candidates(["--target", "source"]) == ["source tree/"]


def test_completion_scripts_cover_supported_shells(capsys: Any) -> None:
    for shell in ("zsh", "bash", "fish"):
        assert run_completions([shell]) == 0
        output = capsys.readouterr().out
        assert "completions --candidates" in output


def test_bash_completion_preserves_candidates_with_spaces(capsys: Any) -> None:
    assert run_completions(["bash"]) == 0
    output = capsys.readouterr().out
    assert 'COMPREPLY=("${candidates[@]}")' in output
    assert "while IFS= read -r candidate" in output
    assert "mapfile" not in output


def test_completion_rejects_unknown_shell(capsys: Any) -> None:
    assert run_completions(["powershell\x1b]52;c;payload\x07"]) == 2
    error = capsys.readouterr().err
    assert "Choose zsh, bash, or fish" in error
    assert "\x1b" not in error
    assert "\\x1b" in error
