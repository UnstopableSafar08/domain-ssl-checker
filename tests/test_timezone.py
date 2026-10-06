"""Tests: Nepal Time display handling. No network."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

UTC_NOON = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def test_kathmandu_offset_and_label():
    from ssl_checker import tzutil as tz_mod

    local = tz_mod.to_local(UTC_NOON, "Asia/Kathmandu")
    assert local.utcoffset() == timedelta(hours=5, minutes=45)
    assert tz_mod.fmt_local(UTC_NOON, "Asia/Kathmandu") == "2026-10-03 17:45"
    assert tz_mod.tz_label("Asia/Kathmandu") == "NPT"
    # Default resolution is Kathmandu even with no configuration.
    assert tz_mod.resolve_tz_name() == "Asia/Kathmandu"
    assert tz_mod.tz_label() == "NPT"


def test_invalid_zone_falls_back_to_kathmandu():
    from ssl_checker import tzutil as tz_mod

    assert tz_mod.resolve_tz_name("Nope/Nowhere") == "Asia/Kathmandu"
    assert tz_mod.fmt_local(UTC_NOON, "Nope/Nowhere") == "2026-10-03 17:45"


def test_env_override(monkeypatch):
    from ssl_checker import tzutil as tz_mod

    monkeypatch.setenv("SSL_DISPLAY_TZ", "UTC")
    assert tz_mod.resolve_tz_name() == "UTC"
    assert tz_mod.tz_label() == "UTC"
    assert tz_mod.fmt_local(UTC_NOON) == "2026-10-03 12:00"


def test_db_setting_validation_and_precedence(tmp_path, monkeypatch):
    from ssl_checker import db as db_mod

    path = db_mod.init_db(str(tmp_path / "tz.db"))
    assert db_mod.get_setting(path, "display_timezone") == "Asia/Kathmandu"
    monkeypatch.setenv("SSL_DISPLAY_TZ", "UTC")
    assert db_mod.get_setting(path, "display_timezone") == "UTC"
    db_mod.set_setting(path, "display_timezone", "Asia/Kathmandu")
    assert db_mod.get_setting(path, "display_timezone") == "Asia/Kathmandu"  # db wins
    for bad in ("Mars/Olympus", "UTC;DROP", "x" * 65):
        try:
            db_mod.set_setting(path, "display_timezone", bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted bad timezone {bad}")
    assert db_mod.set_setting(path, "display_timezone", "UTC") == "UTC"


def test_expires_str_uses_npt_by_default():
    from ssl_checker.checker import CertResult

    r = CertResult(domain="x.com", port=443, success=True,
                   expires_on=UTC_NOON, days_remaining=10)
    assert r.expires_str() == "2026-10-03 17:45"
    assert r.expires_str("UTC") == "2026-10-03 12:00"
    # Machine-readable field stays UTC.
    assert r.to_dict()["expires_on"] == "2026-10-03T12:00:00+00:00"


def test_alert_slot_follows_local_day():
    from ssl_checker import scheduler as sched_mod

    late = datetime(2026, 5, 4, 23, 30, tzinfo=timezone.utc)  # 05:15 NPT next day
    assert sched_mod.alert_slot("daily", late) == "2026-05-04"  # legacy UTC default
    assert sched_mod.alert_slot("daily", late, tz_name="Asia/Kathmandu") == "2026-05-05"
    assert sched_mod.alert_slot("30d", late, tz_name="Asia/Kathmandu") == ""


def test_render_table_npt_header():
    from ssl_checker import render as rd
    from ssl_checker.checker import CertResult

    r = CertResult(domain="x.com", port=443, success=True,
                   expires_on=UTC_NOON, days_remaining=10, status="OK")
    table = rd.render_table([r])
    assert "Expires On (NPT)" in table
    assert "2026-10-03 17:45" in table


def test_teams_card_npt():
    from ssl_checker import notify_teams as teams_mod
    from ssl_checker.checker import CertResult

    r = CertResult(domain="x.com", port=443, success=True,
                   expires_on=UTC_NOON, days_remaining=10, status="WARNING")
    card = teams_mod.build_adaptive_card([r], {"expired": 0, "critical": 0, "warning": 1,
                                               "failed": 0, "ok": 0, "total": 1})
    import json as _json

    text = _json.dumps(card)
    assert "NPT" in text and "2026-10-03 17:45" in text
    assert "UTC" not in text


def test_web_injects_tz_tokens(tmp_path):
    from ssl_checker.web import create_app

    app = create_app(db_path=str(tmp_path / "webtz.db"), enable_scheduler=False, default_file="")
    html = app.test_client().get("/").data.decode()
    assert "__DISPLAY_TZ__" not in html and "__TZ_LABEL__" not in html
    assert "Asia/Kathmandu" in html
    assert "Expires On (NPT)" in html
    assert "Sent (NPT)" in html
