"""Tests: render + web security (SSRF, CSRF, limits). Network mocked."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ssl_checker import evaluate as ev
from ssl_checker import render as rd
from ssl_checker.checker import CertResult


def _res(domain, days=None, ok=True, status=None):
    r = CertResult(domain=domain, port=443, success=ok,
                   days_remaining=days if ok else None, status=status or "OK")
    if ok and days is not None:
        r.expires_on = datetime.now(timezone.utc) + timedelta(days=days)
        r.issuer = "CN=Test CA"
    else:
        r.error = "DNS failure: nope"
    return r


def test_render_table_and_csv_json_html():
    results = [_res("b.com", 5, status="CRITICAL"), _res("bad.invalid", ok=False, status="ERROR")]
    ev.apply_status(results)
    table = rd.render_table(results)
    assert "Domain" in table and "Errors" in table
    assert "bad.invalid" in table
    csv_text = rd.render_csv(results)
    assert csv_text.startswith("domain,port")
    js = rd.render_json(results, ev.summarize(results))
    assert '"domain"' in js
    page = rd.render_html(results, ev.summarize(results))
    assert "<table" in page and "b.com" in page


def test_html_escapes_xss():
    results = [_res('<script>alert(1)</script>.com', 90, status="OK")]
    page = rd.render_html(results, ev.summarize(results))
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page


def test_web_ssrf_private_blocked():
    from ssl_checker.web import is_private_target

    blocked, _ = is_private_target("127.0.0.1")
    assert blocked is True
    blocked10, _ = is_private_target("10.0.0.5")
    assert blocked10 is True


def _test_app(tmp_path, **kwargs):
    """App bound to an isolated temp DB (never touches the real dev database)."""
    from ssl_checker.web import create_app

    kwargs.setdefault("db_path", str(tmp_path / "test.db"))
    kwargs.setdefault("enable_scheduler", False)
    kwargs.setdefault("default_file", "")
    app = create_app(**kwargs)
    app.config.update(TESTING=True)
    return app


def test_web_api_check_blocks_private(tmp_path):
    app = _test_app(tmp_path, allow_private=False)
    client = app.test_client()
    # fetch CSRF token via index page session
    client.get("/")
    with client.session_transaction() as sess:
        token = sess.get("csrf_token", "")
    resp = client.post("/api/check", json={"domains_text": "127.0.0.1"},
                       headers={"X-CSRF-Token": token})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["summary"]["failed"] == 1
    assert "SSRF" in data["results"][0]["error"]


def test_web_api_check_csrf_enforced(tmp_path):
    app = _test_app(tmp_path)
    client = app.test_client()
    resp = client.post("/api/check", json={"domains_text": "example.com"})
    assert resp.status_code == 403


def test_web_api_check_limit_500(tmp_path):
    app = _test_app(tmp_path)
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as sess:
        token = sess.get("csrf_token", "")
    big = "\n".join(f"d{i}.example.com" for i in range(501))
    resp = client.post("/api/check", json={"domains_text": big},
                       headers={"X-CSRF-Token": token})
    assert resp.status_code == 400
    assert "Too many" in resp.get_json()["error"]
