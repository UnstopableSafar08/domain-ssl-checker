"""SQLite persistence — production-grade practices, stdlib only.

Design notes:
- One small file (default ``data/ssl_checker.db``, override with
  ``SSL_DB_PATH``). Parent dir is created automatically.
- WAL journal mode + ``busy_timeout`` so the web UI, the background
  scheduler and a CLI can all use the DB concurrently without
  "database is locked" errors.
- ``foreign_keys=ON`` enforced per connection, parameterized queries
  only (no string-interpolated SQL), short-lived connections
  (connect → work → commit → close) with ``check_same_thread=False``.
- Idempotent schema creation + ``schema_migrations`` table so upgrades
  are additive and safe to run on every start.
- Indexes on every hot lookup path; retention pruning for ``checks``.

Tables:
- ``domains`` — the watch list (unique ``domain, port``).
- ``checks`` — one row per domain per scheduled run (history/analytics).
- ``alerts`` — which milestone notifications were already sent, so the
  30d / 15d / daily cadence never spams.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

SCHEMA_VERSION = 3
DEFAULT_DB_PATH = "data/ssl_checker.db"

# Secret keys are never returned in full by the settings API (masked only).
SECRET_KEYS = {"teams_webhook_url"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (domain, port)
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    expires_on TEXT,
    days_remaining INTEGER,
    status TEXT NOT NULL DEFAULT 'ERROR',
    issuer TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    ips TEXT NOT NULL DEFAULT '',
    duration_ms REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_checks_domain_time ON checks(domain_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_checks_time ON checks(checked_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    cert_key TEXT NOT NULL DEFAULT '',
    milestone TEXT NOT NULL,
    alert_date TEXT NOT NULL DEFAULT '',
    days_remaining INTEGER,
    status TEXT NOT NULL DEFAULT '',
    sent_at TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT 'teams',
    detail TEXT NOT NULL DEFAULT '',
    UNIQUE (domain_id, cert_key, milestone, alert_date)
);
CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain_id, sent_at DESC);

-- v2: runtime settings managed from the Settings page (key/value store).
-- Secrets (teams_webhook_url) are only ever exposed masked via the API.
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
"""


def resolve_db_path(explicit: str | None = None) -> str:
    """Return the DB file path (explicit arg > ``SSL_DB_PATH`` env > default)."""
    if explicit:
        return explicit
    return os.environ.get("SSL_DB_PATH", DEFAULT_DB_PATH)


def connect(db_path: str) -> sqlite3.Connection:
    """Open a configured connection. Caller owns it (use as context manager)."""
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        # Harden against a deleted/missing dir at runtime (one past cause of
        # "unable to open database file" killing the scheduler thread).
        Path(parent).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db(db_path: str | None = None) -> str:
    """Create parent dirs + schema (idempotent). Returns resolved path."""
    path = resolve_db_path(db_path)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        Path(parent).mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (SCHEMA_VERSION, _utc_iso()),
        )
        conn.commit()
    log.info("DB ready at %s", path)
    return path


def _migrate(conn) -> None:
    """Additive upgrades for pre-existing databases. Never destructive."""
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "checks" in tables:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(checks)").fetchall()}
        if "ips" not in cols:
            conn.execute("ALTER TABLE checks ADD COLUMN ips TEXT NOT NULL DEFAULT ''")
            log.info("Migrated DB: added checks.ips")


def _utc_iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------- domains ---
def seed_from_file(db_path: str, file_path: str, source: str = "seed") -> int:
    """Import ``domains.txt``-style file into the DB. Returns # newly added."""
    from . import parsing as parsing_mod

    try:
        items = parsing_mod.parse_file(file_path)
    except FileNotFoundError:
        log.warning("Seed file not found: %s", file_path)
        return 0
    added = 0
    with connect(db_path) as conn:
        now = _utc_iso()
        for host, port in items:
            cur = conn.execute(
                "INSERT OR IGNORE INTO domains(domain, port, enabled, source, created_at, updated_at)"
                " VALUES (?, ?, 1, ?, ?, ?)",
                (host, port, source, now, now),
            )
            added += cur.rowcount
        conn.commit()
    if added:
        log.info("Seeded %d domain(s) from %s", added, file_path)
    return added


def add_domain(db_path: str, domain: str, port: int = 443, source: str = "manual") -> int:
    """Insert (or fetch existing) domain. Returns the row id."""
    from . import parsing as parsing_mod

    item = parsing_mod.parse_domain_line(f"{domain}:{port}" if port != 443 else domain)
    if item is None:
        raise ValueError(f"Invalid domain: {domain!r}")
    host, clean_port = item
    now = _utc_iso()
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO domains(domain, port, enabled, source, created_at, updated_at)"
            " VALUES (?, ?, 1, ?, ?, ?)",
            (host, clean_port, source, now, now),
        )
        conn.execute(
            "UPDATE domains SET updated_at=? WHERE domain=? AND port=?",
            (now, host, clean_port),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id FROM domains WHERE domain=? AND port=?", (host, clean_port)
        ).fetchone()
        return int(row["id"])


def set_domain_enabled(db_path: str, domain_id: int, enabled: bool) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE domains SET enabled=?, updated_at=? WHERE id=?",
            (1 if enabled else 0, _utc_iso(), domain_id),
        )
        conn.commit()
        return cur.rowcount > 0


def delete_domain(db_path: str, domain_id: int) -> bool:
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM domains WHERE id=?", (domain_id,))
        conn.commit()
        return cur.rowcount > 0


def delete_domains(db_path: str, ids: list[int]) -> int:
    """Bulk delete. Returns number of rows removed. Ignores unknown ids."""
    clean = sorted({int(i) for i in ids if isinstance(i, (int, float)) or (isinstance(i, str) and str(i).isdigit())})
    clean = [i for i in clean if i > 0][:500]
    if not clean:
        return 0
    placeholders = ",".join("?" for _ in clean)
    with connect(db_path) as conn:
        cur = conn.execute(f"DELETE FROM domains WHERE id IN ({placeholders})", clean)
        conn.commit()
        return cur.rowcount


def set_domains_enabled(db_path: str, ids: list[int], enabled: bool) -> int:
    """Bulk enable/disable. Returns number of rows updated."""
    clean = sorted({int(i) for i in ids if isinstance(i, (int, float)) or (isinstance(i, str) and str(i).isdigit())})
    clean = [i for i in clean if i > 0][:500]
    if not clean:
        return 0
    placeholders = ",".join("?" for _ in clean)
    with connect(db_path) as conn:
        cur = conn.execute(
            f"UPDATE domains SET enabled=?, updated_at=? WHERE id IN ({placeholders})",
            [1 if enabled else 0, _utc_iso(), *clean],
        )
        conn.commit()
        return cur.rowcount


def list_domains(db_path: str, only_enabled: bool = False) -> list[dict]:
    """Domains with their latest check joined in (for tables + analytics)."""
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT d.id, d.domain, d.port, d.enabled, d.source,
                   d.created_at, d.updated_at,
                   c.checked_at AS last_checked_at, c.success AS last_success,
                   c.expires_on AS last_expires_on, c.days_remaining AS last_days,
                   c.status AS last_status, c.issuer AS last_issuer,
                   c.note AS last_note, c.error AS last_error, c.ips AS last_ips
            FROM domains d
            LEFT JOIN checks c ON c.id = (
                SELECT id FROM checks WHERE domain_id = d.id ORDER BY checked_at DESC LIMIT 1
            )
            WHERE (? = 0 OR d.enabled = 1)
            ORDER BY
              CASE WHEN c.days_remaining IS NULL THEN 1 ELSE 0 END,
              c.days_remaining ASC, d.domain ASC
            """,
            (1 if only_enabled else 0,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------- checks ----
def record_check(
    db_path: str,
    domain_id: int,
    *,
    success: bool,
    expires_on: str | None,
    days_remaining: int | None,
    status: str,
    issuer: str = "",
    note: str = "",
    error: str = "",
    ips: str = "",
    duration_ms: float = 0.0,
    checked_at: str | None = None,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO checks(domain_id, checked_at, success, expires_on,
                   days_remaining, status, issuer, note, error, ips, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                domain_id,
                checked_at or _utc_iso(),
                1 if success else 0,
                expires_on,
                days_remaining,
                status,
                issuer[:500],
                note[:500],
                error[:500],
                ips[:500],
                duration_ms,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_history(db_path: str, domain_id: int, limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 1000))
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM checks WHERE domain_id=? ORDER BY checked_at DESC LIMIT ?",
            (domain_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_recent_checks(db_path: str, limit: int = 500) -> list[dict]:
    """Latest checks across all domains (newest first) for timeline graphs."""
    limit = max(1, min(limit, 5000))
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT c.*, d.domain, d.port FROM checks c
               JOIN domains d ON d.id = c.domain_id
               ORDER BY c.checked_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def prune_old_checks(db_path: str, keep_days: int = 90) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM checks WHERE checked_at < datetime('now', ?)",
            (f"-{int(keep_days)} days",),
        )
        conn.commit()
        return cur.rowcount


# ---------------------------------------------------------------- alerts ----
def has_alert(
    db_path: str, domain_id: int, cert_key: str, milestone: str, alert_date: str = ""
) -> bool:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE domain_id=? AND cert_key=? AND milestone=? AND alert_date=?",
            (domain_id, cert_key, milestone, alert_date),
        ).fetchone()
        return row is not None


def record_alert(
    db_path: str,
    domain_id: int,
    cert_key: str,
    milestone: str,
    *,
    alert_date: str = "",
    days_remaining: int | None = None,
    status: str = "",
    channel: str = "teams",
    detail: str = "",
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """INSERT OR IGNORE INTO alerts(domain_id, cert_key, milestone, alert_date,
                   days_remaining, status, sent_at, channel, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                domain_id,
                cert_key,
                milestone,
                alert_date,
                days_remaining,
                status,
                _utc_iso(),
                channel,
                detail[:500],
            ),
        )
        conn.commit()


def list_alerts(db_path: str, limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 500))
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT a.*, d.domain, d.port FROM alerts a
               JOIN domains d ON d.id = a.domain_id
               ORDER BY a.sent_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------- analytics ----
def analytics(db_path: str) -> dict:
    """Aggregates powering the dashboard (all SQL, no Python number-crunching)."""
    with connect(db_path) as conn:
        total_domains = conn.execute("SELECT COUNT(*) c FROM domains").fetchone()["c"]
        enabled_domains = conn.execute("SELECT COUNT(*) c FROM domains WHERE enabled=1").fetchone()["c"]
        total_checks = conn.execute("SELECT COUNT(*) c FROM checks").fetchone()["c"]
        last_check = conn.execute("SELECT MAX(checked_at) m FROM checks").fetchone()["m"]
        total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

        # Status distribution over latest check per enabled domain.
        dist_rows = conn.execute(
            """
            SELECT COALESCE(c.status, 'NEVER_CHECKED') AS status, COUNT(*) AS n
            FROM domains d
            LEFT JOIN checks c ON c.id = (
                SELECT id FROM checks WHERE domain_id = d.id ORDER BY checked_at DESC LIMIT 1
            )
            WHERE d.enabled = 1
            GROUP BY status
            """
        ).fetchall()

        # Expiry buckets over latest successful checks.
        bucket_rows = conn.execute(
            """
            SELECT
              SUM(CASE WHEN c.days_remaining IS NULL THEN 1 ELSE 0 END) AS no_data,
              SUM(CASE WHEN c.days_remaining < 0 THEN 1 ELSE 0 END) AS expired,
              SUM(CASE WHEN c.days_remaining BETWEEN 0 AND 7 THEN 1 ELSE 0 END) AS d0_7,
              SUM(CASE WHEN c.days_remaining BETWEEN 8 AND 14 THEN 1 ELSE 0 END) AS d8_14,
              SUM(CASE WHEN c.days_remaining BETWEEN 15 AND 30 THEN 1 ELSE 0 END) AS d15_30,
              SUM(CASE WHEN c.days_remaining BETWEEN 31 AND 60 THEN 1 ELSE 0 END) AS d31_60,
              SUM(CASE WHEN c.days_remaining > 60 THEN 1 ELSE 0 END) AS d60p
            FROM domains d
            LEFT JOIN checks c ON c.id = (
                SELECT id FROM checks WHERE domain_id = d.id ORDER BY checked_at DESC LIMIT 1
            )
            WHERE d.enabled = 1
            """
        ).fetchone()

        # Checks per day (last 14 days) + failures per day.
        daily_rows = conn.execute(
            """
            -- Nepal days: +5:45 has no DST so stacked modifiers are exact.
            SELECT substr(datetime(checked_at, '+5 hours', '+45 minutes'), 1, 10) AS day,
                   COUNT(*) AS checks,
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed
            FROM checks
            WHERE checked_at >= datetime('now', '-14 days')
            GROUP BY day ORDER BY day ASC
            """
        ).fetchall()

        # Alerts per milestone.
        milestone_rows = conn.execute(
            "SELECT milestone, COUNT(*) AS n FROM alerts GROUP BY milestone"
        ).fetchall()

    return {
        "totals": {
            "domains": total_domains,
            "enabled": enabled_domains,
            "checks": total_checks,
            "alerts": total_alerts,
            "last_check_at": last_check,
        },
        "status_distribution": {r["status"]: r["n"] for r in dist_rows},
        "expiry_buckets": dict(bucket_rows) if bucket_rows else {},
        "daily": [dict(r) for r in daily_rows],
        "alerts_by_milestone": {r["milestone"]: r["n"] for r in milestone_rows},
    }


# -------------------------------------------------------------- settings ----
#: All manageable settings, their defaults and what they do.
#: Resolution order everywhere: DB value (Settings page) > env var > default.
SETTING_DEFS: dict[str, dict] = {
    "teams_webhook_url": {
        "default": "",
        "env": "TEAMS_WEBHOOK_URL",
        "label": "Teams webhook URL",
        "help": "Power Automate / Workflows webhook. Empty = use the TEAMS_WEBHOOK_URL environment variable.",
        "secret": True,
    },
    "teams_format": {
        "default": "adaptive",
        "env": "SSL_TEAMS_FORMAT",
        "label": "Teams card format",
        "help": "adaptive (modern) or messagecard (legacy).",
    },
    "notifications_enabled": {
        "default": "1",
        "env": "SSL_NOTIFICATIONS_ENABLED",
        "label": "Expiry notifications",
        "help": "Off = record checks but never send Teams alerts.",
    },
    "check_interval_seconds": {
        "default": "300",
        "env": "SSL_CHECK_INTERVAL_SECONDS",
        "label": "Check interval (seconds)",
        "help": "How often every monitored domain is re-checked. 60–86400; applies live.",
    },
    "check_timeout_seconds": {
        "default": "5.0",
        "env": "SSL_CHECK_TIMEOUT",
        "label": "TLS timeout (seconds)",
        "help": "Per-connection TLS timeout. 1–60.",
    },
    "check_workers": {
        "default": "20",
        "env": "SSL_CHECK_WORKERS",
        "label": "Checker workers",
        "help": "Concurrent TLS connections per cycle. 1–100.",
    },
    "ui_url": {
        "default": "",
        "env": "SSL_UI_URL",
        "label": "Public UI URL",
        "help": "Link included in Teams cards, e.g. https://ssl.example.com.",
    },
    "allow_private": {
        "default": "0",
        "env": "SSL_ALLOW_PRIVATE",
        "label": "Allow private targets",
        "help": "Off = block private/loopback/link-local targets (SSRF protection).",
    },
    "display_timezone": {
        "default": "Asia/Kathmandu",
        "env": "SSL_DISPLAY_TZ",
        "label": "Display timezone",
        "help": "IANA zone for all displayed times (storage stays UTC). E.g. Asia/Kathmandu, UTC.",
    },
}


def _validate_setting(key: str, value: str) -> str:
    """Validate + normalize a setting value. Raises ``ValueError`` if bad."""
    v = (value or "").strip()
    if key == "teams_format":
        if v.lower() not in ("adaptive", "messagecard"):
            raise ValueError("teams_format must be 'adaptive' or 'messagecard'")
        return v.lower()
    if key in ("notifications_enabled", "allow_private"):
        if v.lower() in ("1", "true", "yes", "on"):
            return "1"
        if v.lower() in ("0", "false", "no", "off"):
            return "0"
        raise ValueError(f"{key} must be true/false (or 1/0)")
    if key == "check_interval_seconds":
        try:
            iv = int(float(v))
        except ValueError:
            raise ValueError("check_interval_seconds must be a number (60–86400)")
        if not 60 <= iv <= 86400:
            raise ValueError("check_interval_seconds must be 60–86400")
        return str(iv)
    if key == "check_timeout_seconds":
        try:
            fv = float(v)
        except ValueError:
            raise ValueError("check_timeout_seconds must be a number (1–60)")
        if not 1 <= fv <= 60:
            raise ValueError("check_timeout_seconds must be 1–60")
        return str(fv)
    if key == "check_workers":
        try:
            iv = int(float(v))
        except ValueError:
            raise ValueError("check_workers must be a number (1–100)")
        if not 1 <= iv <= 100:
            raise ValueError("check_workers must be 1–100")
        return str(iv)
    if key == "ui_url":
        if v and (len(v) > 500 or not v.startswith(("http://", "https://"))):
            raise ValueError("ui_url must be empty or an http(s) URL")
        return v
    if key == "teams_webhook_url":
        if v and (len(v) > 2000 or not v.startswith("https://")):
            raise ValueError("teams_webhook_url must be empty or an https:// URL")
        return v
    if key == "display_timezone":
        if not v:
            return ""
        if len(v) > 64 or not v.replace("_", "").replace("/", "").replace("-", "").replace("+", "").isalnum():
            raise ValueError("display_timezone must be an IANA name like Asia/Kathmandu or UTC")
        from . import tzutil as tz_mod

        if not tz_mod._is_loadable(v):
            raise ValueError(f"Unknown timezone: {v!r} (try Asia/Kathmandu or UTC)")
        return v
    raise ValueError(f"Unknown setting: {key}")


def get_setting(db_path: str, key: str) -> str:
    """Effective value: DB row > env var > builtin default."""
    if key not in SETTING_DEFS:
        raise ValueError(f"Unknown setting: {key}")
    with connect(db_path) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    # A stored empty string means "no override" — env/default applies.
    if row is not None and row["value"] != "":
        return row["value"]
    env_name = SETTING_DEFS[key].get("env", "")
    if env_name and os.environ.get(env_name, "").strip() != "":
        return os.environ[env_name].strip()
    return SETTING_DEFS[key]["default"]


def get_settings_view(db_path: str) -> dict:
    """Full settings view for the UI. Secrets are masked, never returned whole."""
    from . import notify_teams as teams_mod

    items: dict[str, dict] = {}
    for key, meta in SETTING_DEFS.items():
        value = get_setting(db_path, key)
        with connect(db_path) as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        from_db = row is not None and row["value"] != ""
        env_name = meta.get("env", "")
        from_env = (not from_db) and bool(env_name and os.environ.get(env_name, "").strip())
        entry: dict = {
            "label": meta.get("label", key),
            "help": meta.get("help", ""),
            "default": meta.get("default", ""),
            "env": env_name,
            "source": "db" if from_db else ("env" if from_env else "default"),
        }
        if key in SECRET_KEYS:
            entry["configured"] = bool(value)
            entry["value"] = ""  # never ship the secret to the browser
            entry["masked"] = teams_mod.mask_url(value) if value else "(not set)"
        else:
            entry["value"] = value
        items[key] = entry
    return {"settings": items}


def set_setting(db_path: str, key: str, value: str) -> str:
    """Validate + persist one setting. Returns the normalized value."""
    if key not in SETTING_DEFS:
        raise ValueError(f"Unknown setting: {key}")
    clean = _validate_setting(key, value)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, clean, _utc_iso()),
        )
        conn.commit()
    log.info("Setting updated: %s (source=db)", key)
    return clean


def clear_setting(db_path: str, key: str) -> None:
    """Remove the DB override so env/default applies again."""
    if key not in SETTING_DEFS:
        raise ValueError(f"Unknown setting: {key}")
    with connect(db_path) as conn:
        conn.execute("DELETE FROM settings WHERE key=?", (key,))
        conn.commit()
    log.info("Setting cleared (back to env/default): %s", key)
