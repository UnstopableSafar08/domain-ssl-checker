"""Tests: days-remaining, status classification, sorting. No network."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ssl_checker import evaluate as ev
from ssl_checker.checker import CertResult, days_between


def _now():
    return datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def test_days_between_whole_days():
    now = _now()
    assert days_between(now + timedelta(days=1, hours=20), now) == 1
    assert days_between(now + timedelta(hours=5), now) == 0
    assert days_between(now - timedelta(hours=12), now) == -1
    assert days_between(now - timedelta(days=3), now) == -3


def test_classify_thresholds():
    assert ev.classify(-1, True) == "EXPIRED"
    assert ev.classify(0, True, critical=7, warning=30) == "CRITICAL"
    assert ev.classify(7, True, critical=7, warning=30) == "CRITICAL"
    assert ev.classify(8, True, critical=7, warning=30) == "WARNING"
    assert ev.classify(30, True, critical=7, warning=30) == "WARNING"
    assert ev.classify(31, True, critical=7, warning=30) == "OK"
    assert ev.classify(None, False) == "ERROR"


def test_custom_thresholds():
    assert ev.classify(5, True, critical=3, warning=10) == "WARNING"
    assert ev.classify(3, True, critical=3, warning=10) == "CRITICAL"


def _res(domain: str, days: int | None, ok: bool = True) -> CertResult:
    r = CertResult(domain=domain, port=443, success=ok, days_remaining=days)
    if ok and days is not None:
        r.expires_on = _now() + timedelta(days=days)
    r.status = ev.classify(days, ok)
    return r


def test_sorting_soonest_first_expired_first():
    a = _res("c-ok.com", 60)
    b = _res("a-crit.com", 2)
    c = _res("b-exp.com", -5)
    d = _res("d-warn.com", 10)
    good, bad = ev.sort_results([a, b, c, d])
    assert [r.domain for r in good] == ["b-exp.com", "a-crit.com", "d-warn.com", "c-ok.com"]


def test_errors_separate():
    ok = _res("good.com", 90)
    bad = _res("bad.invalid", None, ok=False)
    good, errors = ev.sort_results([ok, bad])
    assert [r.domain for r in good] == ["good.com"]
    assert [r.domain for r in errors] == ["bad.invalid"]


def test_summarize_and_exit_codes():
    results = [_res("e.com", -1), _res("c.com", 2), _res("w.com", 10), _res("o.com", 90), _res("f.invalid", None, False)]
    ev.apply_status(results)
    s = ev.summarize(results)
    assert s == {"total": 5, "ok": 1, "warning": 1, "critical": 1, "expired": 1, "failed": 1}
    assert ev.exit_code(s) == 2
    assert ev.exit_code({"total": 1, "ok": 1, "warning": 0, "critical": 0, "expired": 0, "failed": 0}) == 0
    assert ev.exit_code({"total": 2, "ok": 1, "warning": 1, "critical": 0, "expired": 0, "failed": 0}) == 1


def test_should_notify_rules():
    all_ok = {"total": 1, "ok": 1, "warning": 0, "critical": 0, "expired": 0, "failed": 0}
    assert ev.should_notify(all_ok, "warning") is False
    assert ev.should_notify(all_ok, "always") is True
    warn = dict(all_ok, warning=1, total=2, ok=1)
    assert ev.should_notify(warn, "warning") is True
    assert ev.should_notify(warn, "critical") is False
    crit = dict(all_ok, critical=1, total=2, ok=1)
    assert ev.should_notify(crit, "critical") is True
    failed = dict(all_ok, failed=1, total=2, ok=1)
    assert ev.should_notify(failed, "warning") is True
