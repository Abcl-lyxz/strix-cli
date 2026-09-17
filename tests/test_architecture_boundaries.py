"""Executable dependency rules for the ports-and-adapters core."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1] / "strix"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def _module_assignments(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        target = node.target if isinstance(node, ast.AnnAssign) else None
        targets = node.targets if isinstance(node, ast.Assign) else []
        for candidate in [target] if target is not None else targets:
            if isinstance(candidate, ast.Name):
                names.add(candidate.id)
    return names


def test_domain_is_pure() -> None:
    violations = [
        f"{path.name} -> {imported}"
        for path in (ROOT / "domain").glob("*.py")
        for imported in _imports(path)
        if imported.startswith("strix.") and not imported.startswith("strix.domain")
    ]
    assert violations == []


def test_ports_only_depend_on_domain_inside_strix() -> None:
    violations = [
        f"{path.name} -> {imported}"
        for path in (ROOT / "ports").glob("*.py")
        for imported in _imports(path)
        if imported.startswith("strix.")
        and not imported.startswith(("strix.domain", "strix.ports"))
    ]
    assert violations == []


def test_application_does_not_depend_on_delivery_or_adapter_layers() -> None:
    forbidden = ("strix.interface", "strix.tools", "strix.adapters", "strix.runtime")
    violations = [
        f"{path.name} -> {imported}"
        for path in (ROOT / "application").glob("*.py")
        for imported in _imports(path)
        if imported.startswith(forbidden)
    ]
    assert violations == []


def test_mcp_session_does_not_depend_on_client() -> None:
    imports = _imports(ROOT / "tools" / "mcp" / "session.py")
    assert "strix.tools.mcp.client" not in imports


def test_removed_scan_global_accessors_do_not_return() -> None:
    production = [path for path in ROOT.rglob("*.py") if "__pycache__" not in path.parts]
    offenders = [
        str(path.relative_to(ROOT))
        for path in production
        if "get_global_report_state" in path.read_text(encoding="utf-8")
        or "set_global_report_state" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_scan_owned_tool_state_is_not_stored_in_module_globals() -> None:
    forbidden = {
        "_coverage_storage",
        "_notes_storage",
        "_todos_storage",
        "_MODELS",
        "_sessions",
        "_jobs",
        "_spill",
        "_SESSION_CACHE",
        "_default_service",
    }
    offenders = [
        f"{path.relative_to(ROOT)}:{name}"
        for path in ROOT.rglob("*.py")
        for name in forbidden
        if name in _module_assignments(path)
    ]
    assert offenders == []


def test_interface_does_not_read_route_health_artifact() -> None:
    offenders = [
        str(path.relative_to(ROOT))
        for path in (ROOT / "interface").rglob("*.py")
        if '"routes.json"' in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_reporting_god_module_was_removed() -> None:
    assert not (ROOT / "tools" / "reporting" / "tool.py").exists()
    assert {
        path.name
        for path in (ROOT / "tools" / "reporting").glob("*.py")
        if path.name != "__init__.py"
    } == {
        "context.py",
        "dependencies.py",
        "queries.py",
        "revisions.py",
        "validation.py",
        "vulnerabilities.py",
    }
