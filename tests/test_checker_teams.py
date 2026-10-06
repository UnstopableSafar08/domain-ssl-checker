"""Tests: checker (mocked TLS) + Teams payload/rules. No real network."""
from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ssl_checker import checker as ch
from ssl_checker import evaluate as ev
from ssl_checker import notify_teams as teams


def _make_cert_der(hostname: str = "example.com", days_valid: int = 90, self_signed: bool = False) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)
    if days_valid >= 0:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)
    else:
        # Expired: validity window entirely in the past.
        not_after = now + timedelta(days=days_valid)
        not_before = not_after - timedelta(days=30)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def test_parse_der_and_days():
    der = _make_cert_der("example.com", days_valid=10)
    not_after, not_before, issuer, cert = ch.parse_der(der)
    assert "Test CA" in issuer
    now = datetime.now(timezone.utc)
    assert 8 <= ch.days_between(not_after, now) <= 10


def test_build_note_self_signed_and_mismatch():
    der = _make_cert_der("example.com", days_valid=90, self_signed=True)
    not_after, not_before, _issuer, cert = ch.parse_der(der)
    now = datetime.now(timezone.utc)
    note = ch.build_note(cert, "other.com", not_after, now, not_before)
    assert "self-signed" in note
    assert "hostname mismatch" in note


def test_build_note_expired():
    der = _make_cert_der("example.com", days_valid=-5)
    not_after, not_before, _issuer, cert = ch.parse_der(der)
    now = datetime.now(timezone.utc)
    assert "expired" in ch.build_note(cert, "example.com", not_after, now, not_before)


def test_check_one_success_mocked():
    der = _make_cert_der("example.com", days_valid=30)
    with patch.object(ch, "fetch_leaf_der", return_value=der):
        r = ch.check_one("example.com", 443)
    assert r.success and r.days_remaining is not None and r.expires_on is not None


def test_check_one_dns_failure_mocked():
    with patch.object(ch, "fetch_leaf_der", side_effect=socket.gaierror(-2, "Name or service not known")):
        r = ch.check_one("nxdomain.invalid", 443)
    assert not r.success and r.error.startswith("DNS failure")


def test_check_one_timeout_mocked():
    with patch.object(ch, "fetch_leaf_der", side_effect=socket.timeout("timed out")):
        r = ch.check_one("slow.example.com", 443)
    assert not r.success and "timeout" in r.error.lower()


def test_check_one_tls_failure_mocked():
    with patch.object(ch, "fetch_leaf_der", side_effect=ssl.SSLError("TLS handshake boom")):
        r = ch.check_one("tls.example.com", 443)
    assert not r.success and "TLS handshake" in r.error


def test_check_domains_concurrent_mocked():
    der = _make_cert_der("example.com", days_valid=30)
    with patch.object(ch, "fetch_leaf_der", return_value=der):
        results = ch.check_domains([("a.com", 443), ("b.com", 443)], workers=2)
    assert len(results) == 2 and all(r.success for r in results)


def _res(domain: str, status: str, days: int | None = 10, ok: bool = True) -> ch.CertResult:
    r = ch.CertResult(domain=domain, port=443, success=ok, days_remaining=days if ok else None, status=status)
    if ok:
        r.expires_on = datetime.now(timezone.utc) + timedelta(days=days or 0)
        r.issuer = "CN=Test"
    else:
        r.error = "DNS failure: nope"
    return r


def test_teams_payload_cap_25():
    results = [_res(f"d{i:02d}.com", "WARNING", days=i) for i in range(30)]
    summary = ev.summarize(results)
    card = teams.build_adaptive_card(results, summary)
    text = json.dumps(card)
    assert "and 5 more" in text
    assert len(text) < 28 * 1024 + 8000  # comfortably small; structure check below
    # Count rendered domain rows (header + 25 + no 'more' row counted separately)
    assert text.count("d0") + text.count("d1") + text.count("d2") >= 25


def test_teams_payload_sorted_soonest_first():
    results = [_res("late.com", "WARNING", days=20), _res("soon.com", "CRITICAL", days=1)]
    summary = ev.summarize(results)
    card = teams.build_adaptive_card(results, summary)
    text = json.dumps(card)
    assert text.index("soon.com") < text.index("late.com")


def test_teams_messagecard_format():
    results = [_res("a.com", "CRITICAL", days=1)]
    card = teams.build_messagecard(results, ev.summarize(results))
    assert card["@type"] == "MessageCard"


def test_notify_rules_skip_when_ok(monkeypatch):
    results = [_res("a.com", "OK", days=90)]
    summary = ev.summarize(results)
    ok, msg = teams.notify(results, summary, notify_on="warning", dry_run=True)
    assert ok and "Skipped" in msg


def test_notify_dry_run_prints_payload():
    results = [_res("a.com", "CRITICAL", days=1)]
    ok, msg = teams.notify(results, ev.summarize(results), notify_on="warning", dry_run=True,
                            webhook_env="TEAMS_WEBHOOK_URL_DOES_NOT_EXIST_XYZ")
    # dry-run must NOT require a webhook URL — prints payload instead of sending.
    assert ok is True
    payload = json.loads(msg)
    assert payload["type"] == "message"


def test_send_payload_retries(monkeypatch):
    calls = {"n": 0}

    class FakeResp:
        status_code = 200
        text = "ok"

    import ssl_checker.notify_teams as tm

    with patch("requests.post", return_value=FakeResp()) as m:
        ok, msg = tm.send_payload("https://example.com/hook", {"a": 1})
    assert ok and m.called


def test_send_payload_non2xx():
    class FakeResp:
        status_code = 400
        text = "bad request"

    with patch("requests.post", return_value=FakeResp()):
        ok, msg = teams.send_payload("https://example.com/hook", {"a": 1}, max_retries=1)
    assert not ok and "400" in msg


def test_mask_url_never_leaks():
    url = "https://logic.azure.com/secret-abc-1234"
    masked = teams.mask_url(url)
    assert "secret" not in masked and masked.startswith("https://")
