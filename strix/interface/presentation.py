"""Small presentation helpers shared by interactive setup projectors."""

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def is_subscription_run(report_state: Any) -> bool:
    """Return the metering mode captured by the run, never ambient config."""
    record = getattr(report_state, "run_record", None)
    return isinstance(record, dict) and record.get("auth_mode") == "subscription"


def _slugify_for_run_name(text: str, max_length: int = 32) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", text.lower().strip()).strip("-")
    if len(text) > max_length:
        text = text[:max_length].rstrip("-")
    return text or "pentest"


def _derive_target_label_for_run_name(  # noqa: PLR0911
    targets_info: list[dict[str, Any]] | None,
) -> str:
    if not targets_info:
        return "pentest"
    first = targets_info[0]
    target_type = first.get("type")
    details = first.get("details", {}) or {}
    original = first.get("original", "") or ""
    if target_type == "web_application":
        url = details.get("target_url", original)
        parsed = urlparse(str(url))
        return str(parsed.netloc or parsed.path or url)
    if target_type == "repository":
        repo = str(details.get("target_repo", original))
        parsed = urlparse(repo)
        name = (parsed.path or repo).rstrip("/").split("/")[-1] or repo
        return name.removesuffix(".git")
    if target_type == "local_code":
        path = details.get("target_path", original)
        return str(Path(str(path)).name or path)
    if target_type == "ip_address":
        return str(details.get("target_ip", original) or original)
    if target_type == "api_spec":
        if details.get("source") == "postman_api":
            return "postman-collection"
        spec_path = details.get("target_spec", original)
        return str(Path(str(spec_path)).stem or spec_path)
    return str(original or "pentest")


def generate_run_name(targets_info: list[dict[str, Any]] | None = None) -> str:
    slug = _slugify_for_run_name(_derive_target_label_for_run_name(targets_info))
    return f"{slug}_{secrets.token_hex(2)}"


__all__ = ["generate_run_name", "is_subscription_run"]
