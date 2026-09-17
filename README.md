# Strix v2

Strix is an open-source autonomous AI pentesting tool. This edition uses one terminal TUI as its control plane, a provider-native connection registry, and deterministic task-aware routing.

> Only scan systems you own or are authorized to test. Strix sends real exploit payloads and may change target data.

## Install

Requirements: Python 3.12+, Docker, and credentials for at least one supported provider.

```bash
curl -sSL https://strix.ai/install | bash
strix
```

From this checkout:

```bash
uv sync --frozen
uv run strix
```

`strix` opens the TUI. The only non-interactive utility entry points are:

```bash
strix --help
strix --version
strix doctor
```

Legacy scan, target, provider, route, update, viewer, notification, and headless flags intentionally fail before any scan starts. Configure and run everything from the TUI.

## First scan

1. Run `/connect` and choose a provider adapter. Credentials are saved automatically through the system secret store.
2. Run `/models` to discover and enable models. A normal provider connection does not ask for a Base URL; that field exists only for Custom OpenAI-compatible, proxy, or advanced adapters.
3. Run `/targets add <url-or-path>` or `/attach`.
4. Review `/settings` and `/router`, then run `/start`.

Environment credentials can be detected by provider adapters, but environment variables never silently override the connection, model, or router state selected in the TUI.

## Canonical TUI commands

`/connect`, `/models`, `/router`, `/settings`, `/targets`, `/attach`, `/mcp`, `/sessions`, `/notifications`, `/update`, `/doctor`, `/start`, `/status`, `/agents`, `/findings`, `/trace`, `/viewer`, `/find`, `/editor`, `/new`, `/help`, `/quit`

The command palette and help are generated from the same registry. Removed v1 commands such as `/model`, `/apikey`, `/baseurl`, `/routes`, `/routing`, `/config`, and `/retry` fail with a migration message.

## Provider and router model

- `AppConfig v3` lives at `~/.strix/config.json`. Strix v2 does not migrate, delete, or overwrite `cli-config.json`, legacy routes, or legacy keychain records.
- `/connect` manages provider-native credentials and provider-specific options. `/models` discovers and enables models; it does not select one global model.
- Provider plugins use the `strix.providers` entry-point group and `ProviderAdapter.api_version = 2`.
- The router filters by auth, capabilities, context, circuit state, and budget, then ranks deterministically by task quality, rolling reliability, capability fit, cost, latency, and stable ID.
- A logical turn uses at most three distinct provider routes. It never automatically replays after streamed output or a side-effecting tool call.

## Viewer and artifacts

`/viewer` opens a local read-only browser view for live transcript, agent graph, findings, artifacts, reports, and saved runs. Provider setup, scan commands, uploads, and agent steering are intentionally unavailable over HTTP.

Run artifacts remain in `strix_runs/<run-name>/`, including reports, findings, SARIF, and redacted router decisions. Legacy runs remain viewable; only v2 run schemas can resume.

## Development

```bash
make dev-install
make format
make check-all
```

`make format` is the only formatting target. `make check-all` is read-only and runs Ruff check/format-check, mypy, Bandit, pytest, protocol drift checks, `gofmt`, `go vet`, Go race tests, and frontend type-check/test/build.

## License and upstream credit

Licensed under Apache-2.0. This edition is derived from the open-source [Strix project](https://github.com/usestrix/strix); upstream authors and license notices are retained.
