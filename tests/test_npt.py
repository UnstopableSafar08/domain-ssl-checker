"""Tests: every timestamp surface uses Nepal Standard Time (UTC+5:45)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ssl_checker import db as db_mod
from ssl_checker import render as rd_mod
from ssl_checker.checker import CertResult


def _res_utcjan1():
    r = CertResult(domain="npt.example.com", port=443, success=True,
                   days_remaining=10, status="OK")
    r.expires_on = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    r.issuer = "CN=Test CA"
    return r


def test_render_csv_npt_header_and_value():
    csv_text = rd_mod.render_csv([_res_utcjan1()])
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("domain,port,expires_on_npt,")
    # 2026-01-01 00:00 UTC == 2026-01-01 05:45 NPT
    assert "2026-01-01 05:45" in lines[1]
    assert "+00:00" not in lines[1] and " 00:00," not in lines[1]


def test_render_html_npt_caption():
    page = rd_mod.render_html([_res_utcjan1()], {"total": 1, "ok": 1, "warning": 0,
                                                "critical": 0, "expired": 0, "failed": 0})
    assert "Nepal Standard Time (UTC+05:45)" in page
    assert "2026-01-01 05:45" in page


def test_analytics_daily_buckets_use_nepal_days(tmp_path):
    path = db_mod.init_db(str(tmp_path / "npt.db"))
    did = db_mod.add_domain(path, "npt.example.com", 443)
    # 20:00 UTC yesterday == 01:45 NPT today: UTC and Nepal days always differ.
    utc_dt = (datetime.now(timezone.utc) - timedelta(days=1)).replace(
        hour=20, minute=0, second=0, microsecond=0)
    npt_day = (utc_dt + timedelta(hours=5, minutes=45)).strftime("%Y-%m-%d")
    assert utc_dt.strftime("%Y-%m-%d") != npt_day
    db_mod.record_check(path, did, success=True, expires_on=None, days_remaining=10,
                        status="OK", checked_at=utc_dt.isoformat())
    days = [row["day"] for row in db_mod.analytics(path)["daily"]]
    assert days == [npt_day]


def test_ui_display_timezone_defaults_to_kathmandu(tmp_path):
    path = db_mod.init_db(str(tmp_path / "tz.db"))
    assert db_mod.get_setting(path, "display_timezone") == "Asia/Kathmandu"


def test_export_html_branding_and_style():
    page = rd_mod.render_html([_res_utcjan1()], {"total": 1, "ok": 1, "warning": 0,
                                                "critical": 0, "expired": 0, "failed": 0})
    assert '<a href="https://sagarmalla.info.np">Sagar Malla</a>' in page
    assert "<style>" in page and 'class="footer"' in page
    assert "nth-child(even)" in page
