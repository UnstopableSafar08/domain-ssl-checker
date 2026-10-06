"""Tests: async check-now (never blocks HTTP), overlap guard, survivor scheduler."""
from __future__ import annotations

import threading
import time

from ssl_checker import db as db_mod
from ssl_checker import scheduler as sched_mod


def _client(tmp_path, name="async.db"):
    from ssl_checker.web import create_app

    app = create_app(db_path=str(tmp_path / name), enable_scheduler=False, default_file="")
    app.config.update(TESTING=True)
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as sess:
        token = sess.get("csrf_token", "")
    return client, token, app


def _sched(app):
    return app.config["SSL_SCHEDULER"]


def test_check_now_returns_202_immediately_while_cycle_runs(tmp_path):
    client, token, app = _client(tmp_path)
    sched = _sched(app)
    entered = threading.Event()
    release = threading.Event()

    def fake_run_cycle(*a, **k):
        entered.set()
        assert release.wait(10), "background cycle was never released"
        return {"checked": 0, "alerts_due": 0}

    sched.run_cycle = fake_run_cycle  # type: ignore[method-assign]
    try:
        t0 = time.monotonic()
        r1 = client.post("/api/check-now", json={}, headers={"X-CSRF-Token": token})
        dt = time.monotonic() - t0
        assert r1.status_code == 202, r1.get_json()
        assert r1.get_json()["started"] is True
        assert dt < 5, f"check-now blocked {dt:.1f}s — must return immediately"
        assert entered.wait(5), "background cycle did not start"

        r2 = client.post("/api/check-now", json={}, headers={"X-CSRF-Token": token})
        assert r2.status_code == 200
        assert r2.get_json()["started"] is False
        assert "already running" in r2.get_json()["message"]
    finally:
        release.set()
    deadline = time.monotonic() + 10
    while sched.cycle_running and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not sched.cycle_running


def test_check_now_completes_and_reports_summary(tmp_path):
    """Real cycle over one SSRF-blocked domain: fast, no network, ends with summary."""
    client, token, app = _client(tmp_path)
    db_mod.add_domain(str(tmp_path / "async.db"), "127.0.0.1", 443, source="test")
    r = client.post("/api/check-now", json={}, headers={"X-CSRF-Token": token})
    assert r.status_code == 202
    deadline = time.monotonic() + 20
    last = None
    while time.monotonic() < deadline:
        last = client.get("/api/analytics").get_json()["scheduler"]
        if not last["cycle_running"] and last["last_summary"]:
            break
        time.sleep(0.2)
    assert last["cycle_running"] is False
    assert last["last_summary"]["checked"] == 1


def test_check_now_csrf_enforced(tmp_path):
    client, _token, _app = _client(tmp_path)
    assert client.post("/api/check-now", json={}).status_code == 403


def test_scheduler_survives_failed_first_cycle(tmp_path):
    """The exact production crash: immediate run fails -> thread must stay alive."""
    blocker = tmp_path / "afile"
    blocker.write_text("not a dir")
    sched = sched_mod.Scheduler(str(blocker / "x.db"), interval_seconds=60)
    sched.start(run_immediately=True)
    try:
        time.sleep(0.5)
        assert sched.running, "scheduler thread died on first failed cycle"
        assert sched.last_error, "failure was not recorded"
        assert sched.status()["cycle_running"] is False
    finally:
        sched.stop()


def test_connect_creates_missing_parent_dirs(tmp_path):
    path = str(tmp_path / "nope" / "nested" / "c.db")
    db_mod.init_db(path)
    assert db_mod.list_domains(path) == []
