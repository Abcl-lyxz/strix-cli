"""Bounded NVD, OSV, CISA KEV, and FIRST EPSS client."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import requests

from strix.config import load_settings
from strix.security import redact_secrets
from strix.utils.atomic import atomic_write_text


_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_URL = "https://api.osv.dev/v1/query"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss"


def _root(cache_dir: Path | None = None) -> Path:
    return cache_dir or Path.home() / ".strix" / "intel"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _fresh(path: Path, *, hours: int = 24) -> bool:
    try:
        stamp = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return False
    return datetime.now(UTC) - stamp < timedelta(hours=hours)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return cast("dict[str, Any]", value) if isinstance(value, dict) else None


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False, default=str))


def _get_json(
    url: str,
    *,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    response = requests.get(
        url,
        params=params,
        headers=headers,
        timeout=15,
        allow_redirects=False,
    )
    response.raise_for_status()
    if len(response.content) > 30 * 1024 * 1024:
        raise ValueError("intelligence response exceeds the 30 MiB safety limit")
    value = response.json()
    if not isinstance(value, dict):
        raise TypeError("intelligence service returned an invalid response")
    return cast("dict[str, Any]", value)


def _validate_kev(payload: dict[str, Any]) -> None:
    if not isinstance(payload.get("vulnerabilities"), list):
        raise TypeError("CISA KEV feed has no vulnerability list")


def refresh_intelligence(*, cache_dir: Path | None = None, force: bool = False) -> dict[str, Any]:
    """Refresh daily shared feeds; preserve cached data when a source fails."""
    root = _root(cache_dir)
    results: dict[str, Any] = {"fetched_at": _now(), "sources": {}}
    kev_path = root / "cisa-kev.json"
    if _fresh(kev_path) and not force:
        results["sources"]["cisa_kev"] = {"status": "cached", "path": str(kev_path)}
    else:
        try:
            payload = _get_json(_KEV_URL)
            _validate_kev(payload)
            _write(kev_path, payload)
            results["sources"]["cisa_kev"] = {"status": "updated", "path": str(kev_path)}
        except (requests.RequestException, TypeError, ValueError, OSError) as exc:
            results["sources"]["cisa_kev"] = {
                "status": "stale" if kev_path.is_file() else "unavailable",
                "error": redact_secrets(str(exc)),
            }
    return results


def _nvd(cve: str, root: Path) -> dict[str, Any]:
    path = root / "cve" / f"{cve}.nvd.json"
    cached = _read(path)
    if cached is not None and _fresh(path):
        return cached
    headers = {"apiKey": key} if (key := load_settings().integrations.nvd_api_key) else {}
    payload = _get_json(_NVD_URL, params={"cveId": cve}, headers=headers)
    result = {"source": "NVD", "fetched_at": _now(), "payload": payload}
    _write(path, result)
    return result


def _epss(cve: str, root: Path) -> dict[str, Any]:
    path = root / "cve" / f"{cve}.epss.json"
    cached = _read(path)
    if cached is not None and _fresh(path):
        return cached
    payload = _get_json(_EPSS_URL, params={"cve": cve})
    result = {"source": "FIRST EPSS", "fetched_at": _now(), "payload": payload}
    _write(path, result)
    return result


def _kev(cve: str, root: Path) -> dict[str, Any]:
    refresh_intelligence(cache_dir=root)
    payload = _read(root / "cisa-kev.json") or {}
    match = next(
        (
            item
            for item in payload.get("vulnerabilities", [])
            if isinstance(item, dict) and str(item.get("cveID", "")).upper() == cve
        ),
        None,
    )
    return {
        "source": "CISA KEV",
        "fetched_at": payload.get("dateReleased") or _now(),
        "known_exploited": match is not None,
        "match": match,
    }


def _osv(package: str, ecosystem: str, version: str, root: Path) -> dict[str, Any]:
    safe_key = re.sub(r"[^a-zA-Z0-9_.-]", "_", f"{ecosystem}-{package}-{version}")[:180]
    path = root / "packages" / f"{safe_key}.osv.json"
    cached = _read(path)
    if cached is not None and _fresh(path):
        return cached
    response = requests.post(
        _OSV_URL,
        json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
        timeout=15,
        allow_redirects=False,
    )
    response.raise_for_status()
    if len(response.content) > 10 * 1024 * 1024:
        raise ValueError("OSV response exceeds the 10 MiB safety limit")
    payload = response.json()
    if not isinstance(payload, dict):
        raise TypeError("OSV returned an invalid response")
    result = {"source": "OSV", "fetched_at": _now(), "payload": payload}
    _write(path, result)
    return result


def query_intelligence(
    identifier: str,
    *,
    ecosystem: str = "",
    version: str = "",
    cache_dir: Path | None = None,
) -> dict[str, Any]:
    """Query a CVE or exact package version with explicit confidence."""
    root = _root(cache_dir)
    value = identifier.strip()
    if _CVE.fullmatch(value):
        cve = value.upper()
        sources: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for name, resolver in (("nvd", _nvd), ("epss", _epss), ("cisa_kev", _kev)):
            try:
                sources.append(resolver(cve, root))
            except (requests.RequestException, TypeError, ValueError, OSError) as exc:
                errors.append({"source": name, "error": redact_secrets(str(exc))})
        return {
            "identifier": cve,
            "match_confidence": "exact-identifier",
            "verified_finding": False,
            "sources": sources,
            "errors": errors,
        }
    if not ecosystem.strip() or not version.strip():
        raise ValueError("Package intelligence requires ecosystem and exact version")
    result = _osv(value, ecosystem.strip(), version.strip(), root)
    return {
        "identifier": value,
        "ecosystem": ecosystem,
        "version": version,
        "match_confidence": "exact-package-version",
        "verified_finding": False,
        "sources": [result],
    }


def status(*, cache_dir: Path | None = None) -> dict[str, Any]:
    root = _root(cache_dir)
    files = list(root.rglob("*.json")) if root.is_dir() else []
    return {
        "cache_dir": str(root),
        "entries": len(files),
        "cisa_kev": str(root / "cisa-kev.json"),
        "cisa_kev_fresh": _fresh(root / "cisa-kev.json"),
    }


__all__ = ["query_intelligence", "refresh_intelligence", "status"]
