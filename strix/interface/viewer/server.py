"""Local HTTP server that serves the viewer SPA and a run's data from disk.

Design notes:
- Uses only the standard library (no new runtime dependency). The workload is
  serving static files plus a handful of JSON reads off disk, so an async stack
  buys nothing here.
- Workspace changes use incremental server-sent events and a fresh snapshot on
  reconnect. Historical reports and transcripts are read from disk on demand.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import re
import secrets
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

from strix.core.paths import run_record_path
from strix.interface.viewer.transcript import (
    build_run_state,
    primary_target,
    read_report_markdown,
    read_run_summary,
    read_vulnerabilities,
    severity_counts,
)


logger = logging.getLogger(__name__)


def bundle_dir() -> Path:
    """Directory holding the committed, prebuilt SPA (index.html + assets)."""
    return Path(__file__).resolve().parent / "static"


def bundle_is_built() -> bool:
    return (bundle_dir() / "index.html").is_file()


def _iter_run_dirs(base_dir: Path) -> list[Path]:
    """Every run directory under ``base_dir``, newest first by record mtime."""
    if not base_dir.is_dir():
        return []
    run_dirs = [child for child in base_dir.iterdir() if run_record_path(child).is_file()]
    run_dirs.sort(key=lambda child: run_record_path(child).stat().st_mtime, reverse=True)
    return run_dirs


def run_list_entry(run_dir: Path) -> dict[str, Any]:
    """Compact summary of a single run for the history list."""
    record = read_run_summary(run_dir)
    return {
        "name": record.get("run_name") or run_dir.name,
        "target": primary_target(record),
        "scan_mode": record.get("scan_mode"),
        "status": record.get("status"),
        "start_time": record.get("start_time"),
        "end_time": record.get("end_time"),
        "finished": bool(record.get("finished")),
        "severity_counts": severity_counts(read_vulnerabilities(run_dir)),
    }


def build_runs_payload(base_dir: Path, *, verified: bool = True) -> dict[str, Any]:
    """All local history is available to an authorized workspace client."""
    del verified  # Compatibility for embedders; verification gates were removed.
    run_dirs = _iter_run_dirs(base_dir)
    return {"locked": False, "count": len(run_dirs), "runs": [run_list_entry(d) for d in run_dirs]}


def resolve_run_dir(base_dir: Path, run_param: str | None, default_run_dir: Path) -> Path | None:
    """Resolve a ``?run=`` value to a real run directory under ``base_dir``.

    Returns ``default_run_dir`` when no run is requested. Rejects traversal and
    unknown runs (returns None) so the caller can answer 404.
    """
    if not run_param:
        return default_run_dir
    base = base_dir.resolve()
    candidate = (base / run_param).resolve()
    # Only direct children of the runs base that actually hold a run record.
    if candidate.parent != base or not run_record_path(candidate).is_file():
        return None
    return candidate


# Prefix of the cookie carrying the per-process session capability. The bound
# port is appended (``strix_viewer_session_<port>``) because browsers scope
# cookies by host only, never by port: concurrent viewers on 127.0.0.1 would
# otherwise share one cookie slot and clobber each other's session.
SESSION_COOKIE_PREFIX = "strix_viewer_session"


class _ViewerState:
    def __init__(
        self,
        run_dir: Path,
        assets_dir: Path,
        workspace: Any = None,
    ) -> None:
        self.run_dir = run_dir
        self.workspace = workspace
        self.assets_dir = assets_dir
        # The strix_runs directory that holds the launched run; used to
        # enumerate and resolve other runs for the history list.
        self.base_dir = run_dir.parent
        # Unguessable per-process capability. A short-lived nonce is opened
        # directly for the operator and exchanged for this session cookie.
        # load. It is the request-level authorization the review asked for:
        # reachability of the port (e.g. when bound with ``--host``) is not
        # enough to read run data, steer a live scan, trigger a report, or
        # browse history -- the token is never handed to a caller who merely
        # reaches ``/``.
        self.session_token = secrets.token_urlsafe(32)
        self.bootstrap_nonces: dict[str, float] = {}
        self.bootstrap_lock = threading.Lock()
        # Finalized in ``serve()`` once the port is known (the server binds
        # after this state is constructed); see SESSION_COOKIE_PREFIX.
        self.cookie_name = SESSION_COOKIE_PREFIX

    def mint_bootstrap(self) -> str:
        nonce = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self.bootstrap_lock:
            self.bootstrap_nonces = {
                value: expiry for value, expiry in self.bootstrap_nonces.items() if expiry > now
            }
            self.bootstrap_nonces[nonce] = now + 60.0
        return nonce

    def consume_bootstrap(self, supplied: str) -> bool:
        now = time.monotonic()
        with self.bootstrap_lock:
            expiry = self.bootstrap_nonces.pop(supplied, None)
        return expiry is not None and expiry > now


def _make_handler(state: _ViewerState) -> type[BaseHTTPRequestHandler]:
    class ViewerHandler(BaseHTTPRequestHandler):
        server_version = "StrixViewer/1.0"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            logger.debug(
                "viewer %s - %s",
                self.address_string(),
                re.sub(r"([?&]token=)[^ &\"]+", r"\1<redacted>", format % args),
            )

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path
            try:
                if path.startswith("/api/"):
                    self._handle_api(path, parse_qs(parts.query))
                else:
                    self._handle_static(path, parse_qs(parts.query))
            except BrokenPipeError:
                # The browser closed the connection mid-response (e.g. it
                # navigated away between polls). Not an error.
                logger.debug("viewer client disconnected during %s", path)
            except Exception:
                # A bad request must never kill the worker thread.
                logger.exception("viewer request failed: %s", path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

        def do_POST(self) -> None:
            if not self._has_session() or not self._same_origin():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
            self.send_header("Allow", "GET")
            self.send_header("Content-Type", "application/json")
            body = b'{"error":"viewer is read-only"}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _same_origin(self) -> bool:
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                return False
            origin = self.headers.get("Origin")
            if not origin:
                return True
            parsed = urlsplit(origin)
            return parsed.scheme in {"http", "https"} and parsed.netloc == self.headers.get("Host")

        def _handle_api(  # noqa: PLR0911, PLR0912, PLR0915 - one authenticated endpoint dispatch
            self, path: str, query: dict[str, list[str]]
        ) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            if path == "/api/runs":
                self._send_json(HTTPStatus.OK, build_runs_payload(state.base_dir))
                return
            if path == "/api/capabilities":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "can_steer": False,
                        "workspace": state.workspace is not None,
                        "read_only": True,
                        "initial_run": getattr(state.workspace, "initial_run", None),
                    },
                )
                return
            if path == "/api/app/state" and state.workspace is not None:
                self._send_json(HTTPStatus.OK, state.workspace.snapshot())
                return
            if path == "/api/app/events" and state.workspace is not None:
                self._stream_workspace()
                return
            default = state.workspace.run_dir() if state.workspace is not None else None
            run_dir = resolve_run_dir(
                state.base_dir, (query.get("run") or [""])[0], default or state.run_dir
            )
            if run_dir is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown run"})
                return
            if path == "/api/run":
                self._send_json(HTTPStatus.OK, read_run_summary(run_dir))
            elif path == "/api/vulnerabilities":
                self._send_json(HTTPStatus.OK, read_vulnerabilities(run_dir))
            elif path == "/api/report":
                self._send_json(HTTPStatus.OK, {"markdown": read_report_markdown(run_dir)})
            elif path == "/api/report/pdf":
                from strix.interface.viewer.report_pdf import generate_report_pdf

                content = generate_report_pdf(run_dir)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", 'attachment; filename="strix-report.pdf"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            elif path == "/api/transcript":
                self._send_json(HTTPStatus.OK, build_run_state(run_dir))
            elif path == "/api/artifacts":
                self._send_json(HTTPStatus.OK, {"artifacts": self._artifacts(run_dir)})
            elif path == "/api/artifact":
                requested = (query.get("path") or [""])[0]
                allowed = {entry["path"] for entry in self._artifacts(run_dir)}
                if requested not in allowed:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown artifact"})
                    return
                target = (run_dir / requested).resolve()
                if run_dir.resolve() not in target.parents:
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                    return
                content = target.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition",
                    "attachment; filename*=UTF-8''" + quote(target.name),
                )
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

        @staticmethod
        def _artifacts(run_dir: Path) -> list[dict[str, Any]]:
            files = [
                run_dir / name
                for name in ("penetration_test_report.md", "vulnerabilities.json", "findings.sarif")
            ]
            for folder in ("vulnerabilities", "browser", "artifacts"):
                directory = run_dir / folder
                if directory.is_dir():
                    files.extend(directory.rglob("*"))
            root = run_dir.resolve()
            return [
                {"path": f.relative_to(run_dir).as_posix(), "size": f.stat().st_size}
                for f in files
                if f.is_file() and not f.is_symlink() and root in f.resolve().parents
            ][:2000]

        def _stream_workspace(self) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            previous: dict[str, Any] = {}
            last_heartbeat = 0.0
            try:
                cursor: int | None = int(self.headers.get("Last-Event-ID", ""))
            except ValueError:
                cursor = None
            try:
                while not state.workspace.closed:
                    payload = state.workspace.snapshot(cursor)
                    if previous and payload["state"].get("run_name") != previous.get(
                        "state", {}
                    ).get("run_name"):
                        payload = state.workspace.snapshot()
                    cursor = payload.pop("cursor")
                    delta = {
                        key: value for key, value in payload.items() if value != previous.get(key)
                    }
                    previous = payload
                    if delta:
                        event = "snapshot" if payload.get("reset") else "update"
                        self.wfile.write(
                            (
                                f"id: {cursor}\ndata: {json.dumps({'type': event, **delta})}\n\n"
                            ).encode()
                        )
                        self.wfile.flush()
                    elif time.monotonic() - last_heartbeat >= 5.0:
                        self.wfile.write(
                            (
                                f'id: {cursor}\nevent: heartbeat\ndata: {{"cursor":{cursor}}}\n\n'
                            ).encode()
                        )
                        self.wfile.flush()
                        last_heartbeat = time.monotonic()
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError, TimeoutError, RuntimeError):
                return

        def _cookies(self) -> dict[str, str]:
            jar: dict[str, str] = {}
            for chunk in (self.headers.get("Cookie") or "").split(";"):
                name, sep, value = chunk.strip().partition("=")
                if sep:
                    jar[name] = value
            return jar

        def _has_session(self) -> bool:
            """True when the request carries this process's session capability.

            The cookie is set only when the SPA is served (index.html), so only
            the browser this process handed the page to can pass. A direct
            caller on an exposed port has no cookie and is rejected.
            """
            supplied = self._cookies().get(state.cookie_name, "")
            return bool(supplied) and secrets.compare_digest(supplied, state.session_token)

        def _token_presented(self, query: dict[str, list[str]]) -> bool:
            """True when the request carries the correct bootstrap token.

            The token reaches the operator's browser through the URL printed /
            opened by the process that started the server, a channel an
            arbitrary network caller on an exposed port cannot observe.
            """
            supplied = (query.get("token") or [""])[0]
            return bool(supplied) and state.consume_bootstrap(supplied)

        def _handle_static(self, path: str, query: dict[str, list[str]]) -> None:
            if path in {"", "/"} and "token" in query:
                if not self._token_presented(query):
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {
                            "error": (
                                "Viewer link is invalid, expired, or already used. "
                                "Open it again from Strix."
                            )
                        },
                    )
                    return
                # Exchange the one-time nonce and redirect immediately.  The
                # browser's visible address never retains the capability.
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie",
                    f"{state.cookie_name}={state.session_token}; Path=/; HttpOnly; SameSite=Strict",
                )
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            target = self._resolve_asset(path)
            if target is None:
                # SPA fallback: unknown non-asset routes render index.html so
                # client-side deep links work.
                target = state.assets_dir / "index.html"
            if not target.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            content = target.read_bytes()
            content_type, _ = mimetypes.guess_type(str(target))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def _resolve_asset(self, path: str) -> Path | None:
            rel = unquote(path).lstrip("/")
            if not rel or rel.endswith("/"):
                return None
            root = state.assets_dir.resolve()
            candidate = (root / rel).resolve()
            # Path-traversal guard: never serve outside the bundle root.
            if root != candidate and root not in candidate.parents:
                logger.warning("viewer rejected traversal attempt: %s", path)
                return None
            return candidate if candidate.is_file() else None

        def _send_json(self, status: HTTPStatus, payload: Any) -> None:
            from strix.interface.viewer.workspace import public_value

            # Closing a socket with unread request bytes can discard the error
            # response on Windows. Drain small rejected bodies with a deadline.
            remaining = getattr(self, "_body_remaining", 0)
            if status >= 400 and 0 < remaining <= 1024 * 1024:
                try:
                    self.connection.settimeout(1)
                    self.rfile.read(remaining)
                except (OSError, TimeoutError):
                    pass
                self._body_remaining = 0
            body = json.dumps(public_value(payload)).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ViewerHandler


def authorized_url(base_url: str, token: str) -> str:
    """URL that bootstraps the viewer session for the operator.

    This URL is handed directly to the browser and never displayed by Strix.
    The server consumes the nonce once and redirects to the bare URL.
    """
    return f"{base_url}/?{urlencode({'token': token})}"


def fresh_authorized_url(httpd: ThreadingHTTPServer, base_url: str) -> str:
    """Mint a new 60-second, one-use browser bootstrap for a running viewer."""
    state = getattr(httpd, "_strix_viewer_state", None)
    if not isinstance(state, _ViewerState):
        return base_url
    return authorized_url(base_url, state.mint_bootstrap())


def serve(
    run_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = True,
    workspace: Any = None,
) -> tuple[ThreadingHTTPServer, str, str]:
    """Start the viewer server on a background thread; return (server, url, token).

    ``url`` is always the bare base. The returned nonce is for embedders and is
    never printed by the bundled clients.

    Binds an ephemeral port by default. If a fixed ``port`` is requested but in
    use, falls back to an ephemeral port. The in-TUI launcher owns the server's
    lifetime.

    The browser surface is read-only. ``workspace`` may expose live snapshots,
    but no browser request can dispatch a command or upload data.
    """
    assets_dir = bundle_dir()
    state = _ViewerState(run_dir=run_dir, assets_dir=assets_dir, workspace=workspace)
    handler = _make_handler(state)

    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError:
        if port == 0:
            raise
        logger.info("viewer port %s unavailable, falling back to an ephemeral port", port)
        httpd = ThreadingHTTPServer((host, 0), handler)

    httpd.daemon_threads = True
    bound_port = int(httpd.server_address[1])
    state.cookie_name = f"{SESSION_COOKIE_PREFIX}_{bound_port}"
    url = f"http://{host}:{bound_port}"
    cast("Any", httpd)._strix_viewer_state = state
    bootstrap_nonce = state.mint_bootstrap()

    thread = threading.Thread(target=httpd.serve_forever, name="strix-viewer", daemon=True)
    thread.start()

    if open_browser:
        _open_browser(authorized_url(url, bootstrap_nonce))

    return httpd, url, bootstrap_nonce


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001 - launching the browser is best-effort
        logger.debug("could not open local browser", exc_info=True)


__all__ = [
    "authorized_url",
    "bundle_dir",
    "bundle_is_built",
    "fresh_authorized_url",
    "serve",
]
