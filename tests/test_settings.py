"""Tests: settings store, milestone cadence, scheduler wiring. Network mocked."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ssl_checker import db as db_mod
from ssl_checker import scheduler as sched_mod
from ssl_checker.checker import CertResult


def _db(tmp_path, name="s.db"):
    path = str(tmp_path / name)
    return db_mod.init_db(path)


def _res(domain, days=None, ok=True):
    r = CertResult(domain=domain, port=443, success=ok,
                   days_remaining=days if ok else None)
    if ok and days is not None:
        r.expires_on = datetime.now(timezone.utc) + timedelta(days=days)
        r.issuer = "CN=Test CA"
        r.status = "OK"
    else:
        r.error = "DNS failure: nope"
        r.status = "ERROR"
    return r


# ------------------------------------------------------------ milestones ----
def test_milestone_boundaries():
    m = sched_mod.milestone_for
    assert m(90, True) is None
    assert m(31, True) is None
    assert m(30, True) == "30d"
    assert m(16, True) == "30d"
    assert m(15, True) == "15d"
    assert m(14, True) == "daily"
    assert m(1, True) == "daily"
    assert m(0, True) == "daily"
    assert m(-5, True) == "daily"
    assert m(None, False) == "error-daily"


def test_alert_slot_dates():
    now = datetime(2026, 5, 4, 12, tzinfo=timezone.utc)
    assert sched_mod.alert_slot("30d", now) == ""
    assert sched_mod.alert_slot("15d", now) == ""
    assert sched_mod.alert_slot("daily", now) == "2026-05-04"
    assert sched_mod.alert_slot("error-daily", now) == "2026-05-04"


# -------------------------------------------------------------- settings ----
def test_setting_defaults_and_env(tmp_path, monkeypatch):
    path = _db(tmp_path)
    assert db_mod.get_setting(path, "check_interval_seconds") == "300"
    assert db_mod.get_setting(path, "teams_format") == "adaptive"
    monkeypatch.setenv("SSL_CHECK_INTERVAL_SECONDS", "600")
    assert db_mod.get_setting(path, "check_interval_seconds") == "600"
    db_mod.set_setting(path, "check_interval_seconds", "900")
    assert db_mod.get_setting(path, "check_interval_seconds") == "900"  # db wins
    db_mod.clear_setting(path, "check_interval_seconds")
    assert db_mod.get_setting(path, "check_interval_seconds") == "600"  # back to env


def test_setting_validation(tmp_path):
    path = _db(tmp_path)
    for bad in ("5", "99999", "abc"):
        try:
            db_mod.set_setting(path, "check_interval_seconds", bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted bad interval {bad}")
    try:
        db_mod.set_setting(path, "teams_format", "smoke-signals")
    except ValueError:
        pass
    else:
        raise AssertionError("accepted bad teams_format")
    try:
        db_mod.set_setting(path, "nope", "1")
    except ValueError:
        pass
    else:
        raise AssertionError("accepted unknown setting")
    assert db_mod.set_setting(path, "check_workers", "7") == "7"
    assert db_mod.set_setting(path, "notifications_enabled", "off") == "0"


def test_webhook_never_returned_full(tmp_path):
    path = _db(tmp_path)
    secret = "https://logic.azure.com/super-secret-hook-12345"
    db_mod.set_setting(path, "teams_webhook_url", secret)
    view = db_mod.get_settings_view(path)
    dumped = json.dumps(view)
    assert secret not in dumped
    entry = view["settings"]["teams_webhook_url"]
    assert entry["value"] == ""
    assert entry["configured"] is True
    assert "super-secret" not in entry["masked"]


# ------------------------------------------------------------- scheduler ----
def _sched(path, **kwargs):
    kwargs.setdefault("allow_private", True)
    return sched_mod.Scheduler(path, **kwargs)


def test_scheduler_30d_once_then_silent(tmp_path):
    path = _db(tmp_path)
    db_mod.set_setting(path, "allow_private", "1")
    db_mod.set_setting(path, "teams_webhook_url", "https://db.example.com/hook-a")
    db_mod.add_domain(path, "example.com", 443)
    sched = _sched(path)
    res = _res("example.com", days=20)  # WARNING band -> 30d milestone
    sent = []

    def fake_send(url, payload):
        sent.append(url)
        return True, "accepted"

    with patch("ssl_checker.checker.check_domains", return_value=[res]), \
         patch("ssl_checker.notify_teams.send_payload", side_effect=fake_send):
        first = sched.run_cycle()
        second = sched.run_cycle()
    assert first["alerts_due"] == 1 and first["alerts_sent"] is True
    assert sent == ["https://db.example.com/hook-a"]  # DB value used, once only
    assert second["alerts_due"] == 0  # one-shot milestone consumed


def test_scheduler_daily_repeats_next_day(tmp_path):
    path = _db(tmp_path)
    db_mod.set_setting(path, "allow_private", "1")
    db_mod.set_setting(path, "teams_webhook_url", "https://db.example.com/hook-b")
    db_mod.add_domain(path, "example.com", 443)
    sched = _sched(path)
    day1 = datetime(2026, 5, 4, 12, tzinfo=timezone.utc)
    day2 = datetime(2026, 5, 5, 12, tzinfo=timezone.utc)
    with patch("ssl_checker.checker.check_domains", return_value=[_res("example.com", days=5)]), \
         patch("ssl_checker.notify_teams.send_payload", return_value=(True, "ok")) as sp:
        assert sched.run_cycle(now=day1)["alerts_sent"] is True
        assert sched.run_cycle(now=day1)["alerts_due"] == 0  # same day: silent
        assert sched.run_cycle(now=day2)["alerts_sent"] is True  # next day: again
    assert sp.call_count == 2


def test_scheduler_notifications_off_sends_nothing(tmp_path):
    path = _db(tmp_path)
    db_mod.set_setting(path, "allow_private", "1")
    db_mod.set_setting(path, "teams_webhook_url", "https://db.example.com/hook-c")
    db_mod.set_setting(path, "notifications_enabled", "0")
    db_mod.add_domain(path, "example.com", 443)
    sched = _sched(path)
    with patch("ssl_checker.checker.check_domains", return_value=[_res("example.com", days=3)]), \
         patch("ssl_checker.notify_teams.send_payload") as sp:
        summary = sched.run_cycle()
    assert summary["alerts_due"] == 1 and summary["alerts_sent"] is False
    assert "disabled" in summary["detail"]
    sp.assert_not_called()
    # checks are still recorded
    assert db_mod.analytics(path)["totals"]["checks"] == 1


def test_scheduler_renewal_rearms_one_shot(tmp_path):
    path = _db(tmp_path)
    db_mod.set_setting(path, "allow_private", "1")
    db_mod.set_setting(path, "teams_webhook_url", "https://db.example.com/hook-d")
    db_mod.add_domain(path, "example.com", 443)
    sched = _sched(path)
    old_cert = _res("example.com", days=20)
    new_cert = _res("example.com", days=25)  # renewed: different expires_on
    assert old_cert.expires_on != new_cert.expires_on
    with patch("ssl_checker.notify_teams.send_payload", return_value=(True, "ok")) as sp:
        with patch("ssl_checker.checker.check_domains", return_value=[old_cert]):
            assert sched.run_cycle()["alerts_sent"] is True
        with patch("ssl_checker.checker.check_domains", return_value=[new_cert]):
            assert sched.run_cycle()["alerts_sent"] is True  # re-armed by new cert
    assert sp.call_count == 2


# ------------------------------------------------------------------ API ----
def _client(tmp_path):
    from ssl_checker.web import create_app

    app = create_app(db_path=str(tmp_path / "api.db"), enable_scheduler=False, default_file="")
    app.config.update(TESTING=True)
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as sess:
        token = sess.get("csrf_token", "")
    return client, token, app


def test_settings_api_roundtrip_and_masking(tmp_path):
    client, token, _app = _client(tmp_path)
    secret = "https://logic.azure.com/api-secret-xyz"
    r = client.get("/api/settings")
    assert r.status_code == 200
    assert secret not in r.get_data(as_text=True)

    # invalid value rejected, nothing applied
    r = client.put("/api/settings", json={"check_interval_seconds": "5"},
                   headers={"X-CSRF-Token": token})
    assert r.status_code == 400
    assert "check_interval_seconds" in r.get_json()["errors"]

    r = client.put("/api/settings",
                   json={"check_interval_seconds": "600", "teams_format": "messagecard",
                         "teams_webhook_url": secret},
                   headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert secret not in body  # still masked on the way back
    data = r.get_json()["settings"]
    assert data["check_interval_seconds"]["value"] == "600"
    assert data["check_interval_seconds"]["source"] == "db"
    assert data["teams_webhook_url"]["configured"] is True

    # empty webhook field = untouched
    r = client.put("/api/settings", json={"teams_webhook_url": "", "ui_url": "https://ssl.example.com"},
                   headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    assert r.get_json()["settings"]["teams_webhook_url"]["configured"] is True
    assert r.get_json()["settings"]["ui_url"]["value"] == "https://ssl.example.com"

    # explicit clear falls back to env/default
    r = client.put("/api/settings", json={"clear_webhook": True},
                   headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    assert r.get_json()["settings"]["teams_webhook_url"]["configured"] is False


def test_settings_api_csrf(tmp_path):
    client, _token, _app = _client(tmp_path)
    assert client.put("/api/settings", json={"check_workers": "5"}).status_code == 403
    assert client.post("/api/settings/test", json={}).status_code == 403


def test_settings_test_webhook_uses_db_url(tmp_path):
    client, token, _app = _client(tmp_path)
    # no webhook anywhere -> 400
    r = client.post("/api/settings/test", json={}, headers={"X-CSRF-Token": token})
    assert r.status_code == 400
    db_url = "https://db.example.com/test-hook"
    client.put("/api/settings", json={"teams_webhook_url": db_url},
               headers={"X-CSRF-Token": token})
    with patch("ssl_checker.notify_teams.send_payload", return_value=(True, "accepted")) as sp:
        r = client.post("/api/settings/test", json={}, headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    assert db_url not in r.get_data(as_text=True)  # secret never echoed
    assert sp.call_args[0][0] == db_url


def test_domains_crud_and_scheduler_status(tmp_path):
    client, token, _app = _client(tmp_path)
    r = client.post("/api/domains", json={"domain": "Example.COM", "port": 443},
                    headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    domains = r.get_json()["domains"]
    assert domains[0]["domain"] == "example.com"  # normalized
    did = domains[0]["id"]

    r = client.patch(f"/api/domains/{did}", json={"enabled": False},
                     headers={"X-CSRF-Token": token})
    assert r.get_json()["domains"][0]["enabled"] == 0
    r = client.delete(f"/api/domains/{did}", headers={"X-CSRF-Token": token})
    assert r.get_json()["domains"] == []

    r = client.get("/api/scheduler")
    assert r.status_code == 200
    assert r.get_json()["effective"]["interval_seconds"] >= 60

    r = client.get("/api/analytics")
    assert r.status_code == 200
    assert "expiry_buckets" in r.get_json()
