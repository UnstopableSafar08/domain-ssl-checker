# Build prompt — SSL Checker (CLI + Web + Teams)

You are a senior Python developer with deep SSL/TLS expertise. Target **python3 (3.14)**.

## Goal
Build a small, production-quality Python tool that reads a list of domains,
reports the SSL/TLS certificate expiry date for each one (soonest expiry
first), provides a web UI, and sends alerts to Microsoft Teams through a
webhook. It must work both as a CLI (for cron/Jenkins) and as a web app.

## Input
- A text file (default: domains.txt), one domain per line.
- Accepted line formats: `example.com`, `example.com:8443`,
  `https://example.com` (strip scheme and path).
- Ignore blank lines and lines starting with `#`. Trim, lowercase,
  and remove duplicates.
- Also accept `--domain a.com --domain b.com`.
- In the web UI, domains can be pasted into a textarea or uploaded as a file.

## Core behavior (shared by CLI and web UI, no duplicated logic)
1. For each domain, open a TLS connection (default port 443, 5s timeout)
   with SNI (`server_hostname`) and fetch the leaf certificate in DER form.
2. Parse it with the `cryptography` library and read `notAfter`
   (use `not_valid_after_utc` where available).
3. Days remaining = whole days between notAfter and current UTC time.
4. Fetch the certificate even if it is expired, self-signed, or has a
   hostname mismatch (unverified context for fetching only), and report
   validation problems in a "Note" column.
5. Check domains concurrently (ThreadPoolExecutor, default 20 workers,
   `--workers` to configure).

## Sorting
- Ascending by days remaining: expires in 1 day, 2 days, 3 days, ...
- Already expired certificates come first ("expired X days ago").
- Domains that failed to connect go in a separate "Errors" section at the end.

## Status thresholds
EXPIRED (<0 days), CRITICAL (<=7), WARNING (<=30), OK (>30).
Configurable with `--critical` and `--warning`.

## CLI
- Commands: `check` (default), `serve` (web UI), `notify` (check + send to Teams).
- Console table columns:
  Domain | Port | Expires On (UTC, YYYY-MM-DD HH:MM) | Expires In | Status | Issuer | Note
- `--format table|csv|json|html` and `--output FILE`.
- Colors only on a TTY, with `--no-color` to disable.
- One-line summary: total, ok, warning, critical, expired, failed.
- Exit codes: 0 all OK, 1 any WARNING, 2 any CRITICAL/EXPIRED, 3 tool/usage error.

## Web UI (`serve` command)
- Flask, bound to 127.0.0.1 by default; `--host` and `--port` configurable.
- Single page, clean and responsive, no external CDN (inline CSS/JS only):
  textarea, file upload, "Load default list", "Check" with progress,
  summary cards, sortable/searchable/filterable color-coded table,
  Errors section, Download CSV/JSON/HTML, "Send to Teams", last-checked UTC.
- Security: escape output, validate input, 500 domains / 1 MB limit,
  reject private/loopback/link-local by default (`--allow-private` to allow),
  CSRF token, optional basic auth via env, no debug in production.

## Teams notifications (webhook)
- Workflows (Power Automate) webhook URL. `--teams-format adaptive|messagecard`
  (default adaptive). URL from `TEAMS_WEBHOOK_URL` (or `--teams-webhook-env`).
  Never hardcode, never print, mask in logs.
- Adaptive Card: title icon/color by worst severity, summary counts,
  affected domains sorted soonest-first (domain, expiry UTC, days left),
  timestamp, link if `--ui-url` given.
- Rules: `--notify-on warning|critical|always` (default warning).
  Cap card at top 25 + "and N more" (~28 KB limit).
  Optional state file + `--remind-every 24h` (re-notify on change or cadence).
- HTTP: 10s timeout, 3 retries exp backoff, handle 429/5xx, non-2xx = failure.
  Teams failure logged, never changes cert-check exit code.
- `--dry-run` prints JSON. UI "Send to Teams" calls the same function.

## Error handling
Label: DNS failure, timeout, refused, TLS handshake, no certificate.
One failing domain never stops the run.

## Non-functional
- Python 3.9+ code, developed/tested on 3.14. Deps: `cryptography`, `Flask`, `requests`.
- Type hints + docstrings. Modules: parsing, checker, evaluate, render,
  notify_teams, web, cli. Core independent from Flask.
- `logging` + `--verbose`. No print debugging, no subprocess/shell,
  never write secrets to disk, never disable timeouts.

## Deliverables
1. Project structure, requirements.txt, sample domains.txt.
2. Dockerfile (non-root, minimal) + docker-compose.yml (webhook via env).
3. README (install, usage, Teams webhook setup, env vars, options, exit codes,
   cron entry, Jenkins stage).
4. pytest tests (mock network): parsing, days calc, status, sorting,
   Teams payload (25-cap), notification rules.
5. Sample console output + sample Teams card payload.

## Decisions locked
- Runtime: `python3` (3.14.x). Docker: `python:3.14-slim`.
- HTTP lib: `requests`. Layout: `ssl_checker/` package + `app.py`.
- UI auth envs: `SSL_CHECKER_USER` / `SSL_CHECKER_PASSWORD`
  (Teams needs ONLY `TEAMS_WEBHOOK_URL` — no username/password).
- Secret: `SSL_CHECKER_SECRET_KEY`. State default: `.ssl-checker-state.json`.
