"""Tests: resolved-IPs column (resolver, v3 migration, cycle recording)."""
from __future__ import annotations

import sqlite3

from ssl_checker import db as db_mod
from ssl_checker import scheduler as sched_mod


def test_resolve_one_literal_and_failure():
    assert sched_mod._resolve_one("1.2.3.4") == "1.2.3.4"
    assert sched_mod._resolve_one(" 127.0.0.1 ") == "127.0.0.1"
    assert sched_mod._resolve_one("") == ""
    assert sched_mod._resolve_one("no-such-host.invalid", timeout=3.0) == ""


def test_resolve_one_localhost():
    ips = sched_mod._resolve_one("localhost", timeout=3.0)
    if ips:  # best-effort: resolver-dependent, but must contain loopback when present
        assert "127.0.0.1" in ips


def test_resolve_many_shape_and_dedupe():
    out = sched_mod.resolve_many(["1.2.3.4", "1.2.3.4", "no-such-host.invalid"], timeout=3.0)
    assert out["1.2.3.4"] == "1.2.3.4"
    assert out["no-such-host.invalid"] == ""
    assert sched_mod.resolve_many([]) == {}


_LEGACY_CHECKS = """
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE domains(id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443, enabled INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'manual', created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL, UNIQUE(domain, port));
CREATE TABLE checks(id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL, success INTEGER NOT NULL DEFAULT 0, expires_on TEXT,
    days_remaining INTEGER, status TEXT NOT NULL DEFAULT 'ERROR',
    issuer TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '', duration_ms REAL NOT NULL DEFAULT 0);
"""


def test_v3_migration_adds_ips_column(tmp_path):
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.executescript(_LEGACY_CHECKS)
    conn.commit()
    conn.close()
    db_mod.init_db(path)
    conn = sqlite3.connect(path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(checks)").fetchall()}
    conn.close()
    assert "ips" in cols
    # idempotent: second init must not fail or duplicate
    db_mod.init_db(path)
    did = db_mod.add_domain(path, "example.com", 443)
    db_mod.record_check(path, did, success=False, expires_on=None,
                        days_remaining=None, status="ERROR", error="x", ips="1.2.3.4")
    assert db_mod.list_domains(path)[0]["last_ips"] == "1.2.3.4"


def test_run_cycle_records_ips(tmp_path):
    """SSRF-blocked loopback: no network, deterministic IPs."""
    path = db_mod.init_db(str(tmp_path / "ips.db"))
    db_mod.add_domain(path, "127.0.0.1", 443, source="test")
    sched = sched_mod.Scheduler(path)
    summary = sched.run_cycle()
    assert summary["checked"] == 1
    domains = db_mod.list_domains(path)
    assert domains[0]["last_ips"] == "127.0.0.1"


def test_api_domains_exposes_last_ips(tmp_path):
    from ssl_checker.web import create_app

    app = create_app(db_path=str(tmp_path / "api-ips.db"), enable_scheduler=False, default_file="")
    app.config.update(TESTING=True)
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as sess:
        token = sess.get("csrf_token", "")
    r = client.post("/api/domains", json={"domain": "example.com", "port": 443},
                    headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    rows = r.get_json()["domains"]
    assert rows and "last_ips" in rows[0]
