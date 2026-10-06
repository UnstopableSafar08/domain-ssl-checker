# SSL Checker — Certificate Expiry Monitor

CLI + Web UI + Microsoft Teams alerts. Checks TLS certificates concurrently,
sorts by soonest expiry, and notifies before things break.

## Quick start (python3 — 3.14)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest  # for tests only

# Check the sample list
python3 -m ssl_checker.cli check --file domains.txt

# Or via entry point
python3 app.py check --domain example.com --domain google.com
```

## Usage

```
python3 -m ssl_checker.cli [check|serve|notify|scheduler|domain-add|domain-list|domain-remove|db-seed] [options]
python3 app.py ...            # same (also serves gunicorn app:app)
./start.sh                    # web UI + scheduler in background
./stop.sh                     # stop it
```

| Command | What it does |
|---|---|
| `check` (default) | Check certs, print table/csv/json/html |
| `serve` | Run the Flask web UI + background 5-min checker (default `127.0.0.1:5000`) |
| `notify` | Check + send Adaptive Card to Teams |
| `scheduler` | Run the 5-minute check loop headless (`--once` for a single cycle) |
| `domain-add/list/remove` | Manage the SQLite watch list |
| `db-seed` | Import a domains file into SQLite |

Key options:

```
--file domains.txt --domain a.com --domain b.com
--workers 20 --timeout 5 --critical 7 --warning 30
--format table|csv|json|html --output report.html --no-color --verbose --tz Asia/Kathmandu
serve: --host 127.0.0.1 --port 5000 --allow-private --db data/ssl_checker.db
       --interval 300 --no-scheduler
scheduler: --db data/ssl_checker.db --interval 300 --once
notify: --teams-webhook-env TEAMS_WEBHOOK_URL --teams-format adaptive|messagecard
        --notify-on warning|critical|always --ui-url https://ssl.example.com
        --dry-run --state-file .ssl-checker-state.json --remind-every 24h
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All OK |
| 1 | Any WARNING |
| 2 | Any CRITICAL / EXPIRED / FAILED connection |
| 3 | Tool / usage error (bad file, no domains, fatal) |

A Teams delivery failure is **logged only** — it never changes the exit code.

### Web UI

```bash
python3 -m ssl_checker.cli serve --port 5000
# open http://127.0.0.1:5000
```

Enterprise app shell (no CDN, inline CSS/JS, responsive with mobile nav):
dark sidebar with icon navigation across **Dashboard · Certificates ·
Domains · Analytics · Settings** (deep-linkable via `#/view` hashes),
sticky content header with live check timestamp, and an SVG favicon.
Dashboard cards are clickable drill-downs (e.g. Critical jumps to a
pre-filtered certificate list). Certificates view keeps the textarea +
file upload + *Load default list*, async *Check* with progress bar and
skeleton rows (UI never freezes), sortable columns, search box, status
filter, color-coded badges with status dots, separate Errors section,
Download CSV/JSON/HTML, *Send to Teams*. Focus-visible rings and
keyboard-operable cards/tabs throughout.

Security: output escaped (XSS-safe DOM), 500 domains + 1 MB cap,
SSRF guard (private/loopback/link-local rejected unless `--allow-private`),
CSRF token on POSTs, optional basic auth, security headers, no debug mode.

### Monitored domains, analytics & settings (SQLite-backed)

`serve` keeps a SQLite database (`data/ssl_checker.db`, override with
`SSL_DB_PATH`) and a background thread re-checks every enabled domain
(default every 300 s, configurable). Every outcome is recorded, so the UI
shows history and analytics without re-scanning:

- **Monitored domains** — add / pause / resume / delete, import the pasted
  list, per-domain history, *Check now* button, scheduler status.
- **Analytics** — status mix, expiry buckets, checks-per-day canvas chart
  (failed overlay), recent Teams alerts log. Auto-refreshes every minute.
- **Settings** — manage everything from the UI: Teams webhook URL, card
  format, notifications on/off, check interval / timeout / workers, public
  UI URL, private-target policy. Priority is always
  **Settings page (SQLite) › environment variable › built-in default**,
  with the source (`db`/`env`/`default`) shown per field.
  Secrets are stored server-side and only ever returned masked
  (`https://***abcd`); interval changes apply live on the next cycle.

DB practices: WAL mode + busy timeouts (web, scheduler and CLI can share
the file), foreign keys, parameterized queries only, short-lived
connections, idempotent schema migrations, indexes on hot paths.

### Teams milestone alerts (scheduler)

Instead of alerting on every cycle, each domain notifies on this cadence
(per certificate — a renewal re-arms the one-shots):

| Remaining | Alert |
|---|---|
| 16–30 days | **once** (`30d` milestone) |
| exactly 15 days | **once** (`15d` milestone) |
| 14…1 days, expires-today, expired | **daily** (once per UTC day) |
| connection failures | **daily** while failing |

Due alerts across all domains are batched into **one Teams card per cycle**
(top 25 + “and N more”). Sent milestones live in the `alerts` table, so
restarts never double-send. Use *Send test card* on the Settings page to
verify the webhook without waiting for a milestone.

### Timezone — Nepal Time (NPT, UTC+5:45)

All timestamps are **stored in UTC** (database, CSV/JSON exports, API
payloads) so expiry math never shifts; only the **human-readable display**
converts to Nepal Time: console tables (`Expires On (NPT)`), HTML reports,
Teams cards (`Checked at … NPT`), and every time in the web UI (rendered
via `Intl` in Asia/Kathmandu). The daily alert boundary follows the
Nepalese calendar day. Change it any time via **Settings → Display
timezone** (any IANA zone, e.g. `UTC`), `SSL_DISPLAY_TZ`, or
`check --tz UTC` — storage and day-counts are unaffected.

```bash
export SSL_CHECKER_USER=admin SSL_CHECKER_PASSWORD='use-a-vault-secret'
export SSL_CHECKER_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
python3 -m ssl_checker.cli serve --host 127.0.0.1 --port 5000
# internal domains:
python3 -m ssl_checker.cli serve --allow-private --host 127.0.0.1
```

## Teams webhook setup (Workflows / Power Automate)

1. Teams channel → **⋯ → Workflows** (or *Apps → Workflows*).
2. Template: **Post to a channel when a webhook request is received**.
3. Create → copy the **HTTP POST URL** (long `logic.azure.com` URL).
4. Export it — never commit it:

```bash
export TEAMS_WEBHOOK_URL='https://...logic.azure.com.../triggers/...'
python3 -m ssl_checker.cli notify --notify-on warning --ui-url http://127.0.0.1:5000
```

Verify without spamming:

```bash
python3 -m ssl_checker.cli notify --dry-run | head -c 2000
```

Notes:

- Only the **hook URL** is needed — no username/password. (The
  `SSL_CHECKER_USER/PASSWORD` envs protect the *web UI*, not Teams.)
- Payload is an Adaptive Card (legacy MessageCard via `--teams-format messagecard`).
- Top 25 affected domains + “and N more” keeps it under Teams’ ~28 KB limit.
- `--notify-on warning` (default) sends only when warning/critical/expired/failed exist.
- `--state-file .ssl-checker-state.json --remind-every 24h` re-notifies only on
  status change or once per cadence.
- HTTP: 10 s timeout, 3 retries with exponential backoff on 429/5xx.

### Environment variables

| Var | Purpose | UI setting |
|---|---|---|
| `TEAMS_WEBHOOK_URL` | Teams webhook (or custom name via `--teams-webhook-env`) | Teams webhook URL (DB wins when set) |
| `SSL_TEAMS_FORMAT` | `adaptive`/`messagecard` default | Teams card format |
| `SSL_NOTIFICATIONS_ENABLED` | `1`/`0` master alert switch | Expiry notifications |
| `SSL_CHECK_INTERVAL_SECONDS` | Re-check cadence (default 300) | Check interval |
| `SSL_CHECK_TIMEOUT` / `SSL_CHECK_WORKERS` | Per-cycle TLS tuning | Timeout / workers |
| `SSL_UI_URL` | Link inside Teams cards | Public UI URL |
| `SSL_DISPLAY_TZ` | IANA display zone (default `Asia/Kathmandu`) | Display timezone |
| `SSL_ALLOW_PRIVATE` | `1/true/yes` = allow private targets | Allow private targets |
| `SSL_DB_PATH` | SQLite file (default `data/ssl_checker.db`) | — |
| `SSL_ENABLE_SCHEDULER` | `1` = in-process scheduler under gunicorn | — |
| `SSL_CHECKER_USER` / `SSL_CHECKER_PASSWORD` | Optional UI basic auth | — |
| `SSL_CHECKER_SECRET_KEY` | Flask session/CSRF secret (generate randomly) | — |
| `SSL_DOMAINS_FILE` | Seed file for the DB watch list | — |

Anything in the right column can be changed live on the Settings page —
no restart, no redeploy.

## Docker

```bash
export TEAMS_WEBHOOK_URL='https://...your-webhook...'
docker compose up --build
# UI: http://localhost:5000
```

Compose runs two services sharing one SQLite volume (`ssl-data`):
`ssl-checker` (gunicorn, scheduler **off** to avoid double alerts) and
`scheduler` (the 5-minute loop + milestone Teams alerts).

Image: `python:3.14-slim`, non-root `appuser`, gunicorn.

## Cron (daily 08:00) + Jenkins

```cron
0 8 * * *  cd /opt/ssl-checker && TEAMS_WEBHOOK_URL='https://...' /opt/ssl-checker/.venv/bin/python -m ssl_checker.cli notify --state-file /opt/ssl-checker/.state.json --remind-every 24h --ui-url https://ssl.example.com >> /var/log/ssl-checker.log 2>&1
```

```groovy
stage('SSL Check') {
  steps {
    withCredentials([string(credentialsId: 'teams-webhook-url', variable: 'TEAMS_WEBHOOK_URL')]) {
      sh "python3 -m ssl_checker.cli notify --notify-on warning --ui-url ${env.SSL_UI_URL}"
    }
  }
}
```

## Project layout

```
ssl_checker/  parsing.py checker.py evaluate.py render.py notify_teams.py
              web.py cli.py db.py scheduler.py
app.py  domains.txt  requirements.txt  Dockerfile  docker-compose.yml
data/ssl_checker.db  tests/  samples/  README.md  prompt.md
```

## Tests

```bash
python3 -m pytest -q   # 51 tests
```

Network is fully mocked (no real TLS in tests). Covers: input parsing,
days-remaining math, status/sorting, Teams payload + 25-cap + notify rules,
render escaping, SSRF/CSRF/limits, SQLite CRUD + settings validation +
secret masking, milestone cadence (30d once / 15d once / daily / renewal
re-arm / notifications-off), scheduler DB-webhook precedence, and the
settings/domains/analytics APIs.
