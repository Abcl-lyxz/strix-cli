# Strix — Agent Guide

Strix is an open-source autonomous AI pentesting tool. This file is for AI coding agents that want to **use** Strix (run security scans) or **contribute** to it.

## Using Strix from an agent

Install the agent skills for step-by-step workflows:

```bash
npx skills add usestrix/strix
```

- `penetration-testing-with-strix` — run a headless pentest against code, URLs, domains, or IPs and read results
- `fix-security-vulnerabilities-with-strix` — remediate findings and re-run Strix to verify
- `ci-security-scanning-with-strix` — add PR scanning to CI/CD (self-hosted CLI)

Target-specific workflows built on the same engine:

- `application-security-testing` — whole-product AppSec review: pick the right test per asset, then rank the results
- `web-app-penetration-testing` — black-box pentest of a live web app or staging site
- `api-security-testing` — REST/GraphQL APIs and the OWASP API Security Top 10 (BOLA/IDOR, authz)
- `owasp-top-10-testing` — systematic OWASP Top 10 assessment with honest per-category coverage
- `find-security-vulnerabilities-in-code` — white-box review of a repo or working tree

**Run locally with your model provider:**

- **Open-source CLI (self-hosted):** free, fully local, BYO LLM key, needs Docker. Best for local dev loops, air-gapped/offline, and full control.
  ```bash
  curl -sSL https://strix.ai/install | bash        # install
  export STRIX_LLM="openrouter/z-ai/glm-5.3"        # any LiteLLM model id
  export LLM_API_KEY="<key>"
  strix -n -t ./ --scan-mode quick --max-budget 10  # headless scan; always use -n
  ```
  - Requires Docker running. Scans take minutes (`quick`) to hours (`deep`) — run in the background.
  - Diagnose installation, Docker/VPN/proxy routing, model setup, and container HTTPS with `strix doctor --network`.
  - Bound agent expansion with `--max-agents N` (default `12`, including the root); completed/stopped agents free slots.
  - Exit codes (headless): `0` clean, `1` fatal error, `2` vulnerabilities found. A `0` only covers what was analyzed — check `run.json` (`status`, `llm_usage.cost` vs the budget) before calling a run clean.
  - Artifacts in `strix_runs/<run-name>/`: `penetration_test_report.md`, `vulnerabilities/*.md`, `vulnerabilities.json`, `findings.sarif` (SARIF 2.1.0), `run.json`.

- CLI docs index for LLMs: https://docs.strix.ai/llms.txt (full: https://docs.strix.ai/llms-full.txt).
- Only scan targets the user is authorized to test.

## Contributing to this repo

- Python 3.12+, managed with `uv`. Install dev deps: `make dev-install`.
- Lint/format/type-check/security, all in one: `make check-all` (ruff, mypy, bandit).
- Tests: `uv run pytest`.
- Run from source: `uv run strix --target <target>`.
- Layout: `strix/agents` (agent graph + prompts), `strix/tools` (proxy, browser, terminal, scanners), `strix/runtime` (Docker sandbox), `strix/report` (findings, SARIF), `strix/skills` (internal knowledge packs the pentest agents load — different from the consumer skills in `skills/`), `strix/interface` (CLI/TUI), `containers/` (sandbox image).
- Pre-commit hooks: `make pre-commit` (or `uv run pre-commit install`).
