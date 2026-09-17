# Strix — Agent Guide

Strix v2 is an open-source autonomous AI pentesting tool with a terminal-only control plane.

## Using Strix

Only test targets the user owns or is authorized to assess.

```bash
strix
```

The user completes provider connection, model enablement, targets, settings, and scan launch inside the TUI. External automation must not try to bypass the TUI: v2 has no headless or CI scanning entry point.

The only utility commands outside the TUI are:

```bash
strix --help
strix --version
strix doctor
```

Use `/connect` for provider credentials, `/models` for discovery and enablement, `/targets` for scope, `/settings` for typed scan limits, `/router` for route eligibility and decisions, and `/start` to create the immutable run configuration. `/viewer` is read-only.

## Contributing

- Python 3.12+, managed with `uv`; install with `make dev-install`.
- Format explicitly with `make format`.
- Run the full non-mutating gate with `make check-all`.
- Run from source with `uv run strix`.
- Layout: `strix/agents` (agent graph and prompts), `strix/providers` (ProviderAdapter v2 registry), `strix/tools` (proxy, browser, terminal, scanners), `strix/runtime` (Docker sandbox), `strix/report` (findings and SARIF), `strix/skills` (internal knowledge packs), `strix/interface` (TUI and read-only viewer), and `containers/` (sandbox image).
- Provider plugins register through the `strix.providers` entry-point group and must declare `api_version = 2`.
- The Pydantic protocol v8 models are the source of truth. Run `make protocol-check` after protocol changes.
- Do not add scan/setup flags, environment precedence over TUI state, browser mutations, or a second configuration owner.
