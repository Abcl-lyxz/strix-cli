---
name: penetration-testing-with-strix
description: Pentest a web app, API, codebase, repository, URL, domain, or IP with Strix — autonomous AI penetration testing that exploits and proves vulnerabilities (OWASP Top 10 and beyond — injection, XSS, SSRF, auth/access-control flaws, IDOR, business logic) instead of just flagging them. Runs self-hosted with the open-source CLI, and returns validated findings with proof-of-concept exploits (Markdown, JSON, CSV, SARIF). Use when the user asks to pentest, hack, security-scan, security-audit, or find vulnerabilities in an app, API, website, or repo.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Run a Strix pentest

Run the self-hosted CLI in a Docker sandbox with the user's model provider. Only test targets the user is authorized to assess.

## Prerequisites

1. **Docker running** — check with `docker info`. The first scan pulls the sandbox image automatically.
2. **Strix installed** — check with `strix --version`. Install if missing:
   ```bash
   curl -sSL https://strix.ai/install | bash   # or: pipx install strix-agent
   ```
3. **LLM configured** — two environment variables:
   ```bash
   export STRIX_LLM="openai/gpt-5.4"      # any LiteLLM model id (openai/..., anthropic/..., openrouter/...)
   export LLM_API_KEY="<provider api key>"
   ```
   Ask the user for these if unset. Never hardcode or commit keys.

## Running a scan

Always use `-n` (non-interactive/headless) — the default TUI blocks agents. Always set `--max-budget` unless the user says otherwise.

```bash
# Local code (white-box)
strix -n -t ./ --scan-mode standard --max-budget 10

# Deployed app / API (black-box)
strix -n -t https://staging.example.com --max-budget 20

# Repo + deployed app together (best coverage)
strix -n -t https://github.com/org/app -t https://staging.example.com

# Focused testing with credentials or scope hints
strix -n -t https://app.example.com \
  --instruction "Use credentials user@example.com:pass123. Focus on IDOR and auth bypass."

# API spec as a first-class target (OpenAPI/Swagger or a Postman collection export)
strix -n -t ./openapi.yaml -t https://api.staging.example.com

# Many targets from a file, one per line
strix -n --target-list ./targets.txt --max-budget 30

# Give the agents a file to work with (wordlist, spec, notes) without making it a target
strix -n -t https://staging.example.com --workspace-file ./wordlist.txt --max-budget 20
```

A local path passed with `-t` is mounted into the sandbox **writable** — the agents can read and modify it, so point at a clean checkout, not uncommitted work you care about.

Key flags:

| Flag | Meaning |
|---|---|
| `-t, --target` | URL, repo URL, local path, domain, IP, OpenAPI/Postman spec, or `postman://<uuid>`. Repeatable. |
| `--target-list PATH` | File of targets, one per line (`#` comments allowed). Repeatable, combines with `-t`. |
| `-n, --non-interactive` | Headless, exits on completion. Required for agents. |
| `-m, --scan-mode` | `quick` (minutes) / `standard` (~30 min) / `deep` (hours, default). |
| `--instruction` / `--instruction-file` | Credentials, focus areas, scope rules. |
| `--workspace-file PATH[:DEST]` | Place a file from this machine into `/workspace` read-only before the scan, for a wordlist, a spec, or notes. Repeatable. |
| `--max-budget USD` | Hard LLM spend cap; scan wraps up cleanly at the limit. |
| `--max-turns N` | Per-agent turn cap (default 500). |
| `--resume RUN_NAME` | Resume a prior run from `strix_runs/`, with its agent history and targets. Cannot be combined with `-t`. |
| `--scope-mode` | For code targets: `auto` (diff-scope in CI/headless), `diff` (force changed files only), `full` (whole tree). |
| `--diff-base REF` | Branch or commit that `diff` scope compares against. Defaults to the repo's default branch. |

Scans take minutes (`quick`) to hours (`deep`). Run them in the background and poll for completion rather than blocking.

### Exit codes (headless)

- `0` — finished with no validated vulnerabilities **in what was analyzed**
- `1` — fatal error (missing env vars, Docker down, bad config)
- `2` — vulnerabilities found

A `0` is not proof of full coverage: if `--max-budget`/`--max-turns` is reached before the scan completes, it wraps up early and still exits `0`. When you need assurance the scan finished, give it enough budget and check `strix_runs/<run>/run.json`: a hard budget stop leaves `status: "stopped"`, but an agent that wrapped up early on a budget *warning* still calls `finish_scan` and records `"completed"` — so also sanity-check the run's cost against `--max-budget` and the report's stated coverage before treating a clean result as full coverage.

### Reading results

Artifacts land in `strix_runs/<run-name>/`:

| File | Contents |
|---|---|
| `penetration_test_report.md` | Executive report — read this first. |
| `vulnerabilities/*.md` | One file per validated finding, with PoC and remediation. |
| `vulnerabilities.json` / `vulnerabilities.csv` | All findings as structured JSON / CSV index. |
| `findings.sarif` | SARIF 2.1.0 for GitHub code scanning / ASPM ingestion. |
| `run.json` | Run metadata, status, targets, usage/cost. |

---

## Reporting & next steps

Summarize findings by severity (critical/high/medium/low/info) and include the PoC evidence. To remediate and verify fixes (via either path), use the **fix-security-vulnerabilities-with-strix** skill. To wire scanning into CI/CD, use the **ci-security-scanning-with-strix** skill.

## Safety

Only scan targets the user owns or is authorized to test. The Cloud platform enforces domain verification before external scans; for the OSS CLI, confirm authorization yourself if the target looks like third-party infrastructure.
