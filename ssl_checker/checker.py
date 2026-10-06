"""TLS certificate fetching and analysis.

Core behavior (shared by CLI and web UI):
1. Open a TLS connection (default port 443, 5s timeout) with SNI and
   fetch the leaf certificate in DER form.
2. Parse it with ``cryptography`` and read ``notAfter``.
3. Days remaining = whole days between notAfter and current UTC time.
4. Fetch even if expired / self-signed / hostname-mismatched
   (unverified context for fetching only) and report problems in ``Note``.
5. Concurrent fetching via ``ThreadPoolExecutor``.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
DEFAULT_WORKERS = 20


@dataclass
class CertResult:
    """Result for a single (domain, port)."""

    domain: str
    port: int
    success: bool = False
    expires_on: datetime | None = None
    days_remaining: int | None = None
    issuer: str = ""
    note: str = ""
    error: str = ""
    status: str = "ERROR"  # filled by evaluate.classify
    checked_at: datetime | None = None

    def expires_str(self, tz_name: str | None = None) -> str:
        """``YYYY-MM-DD HH:MM`` in the display zone (default Nepal Time) or ``—``."""
        from . import tzutil as tz_mod

        if self.expires_on is None:
            return "—"
        return tz_mod.fmt_local(self.expires_on, tz_name)

    def expires_in_str(self) -> str:
        """Human ``Expires In`` cell, e.g. ``12 days`` / ``expired 3 days ago``."""
        if not self.success or self.days_remaining is None:
            return "—"
        d = self.days_remaining
        if d < 0:
            n = abs(d)
            return f"expired {n} day{'s' if n != 1 else ''} ago"
        if d == 0:
            return "expires today"
        return f"{d} day{'s' if d != 1 else ''}"

    def to_dict(self, tz_name: str | None = None) -> dict:
        exp = self.expires_on
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return {
            "domain": self.domain,
            "port": self.port,
            "success": self.success,
            # Machine-readable stays UTC; humans read expires_on_display.
            "expires_on": exp.astimezone(timezone.utc).isoformat() if exp else None,
            "expires_on_display": self.expires_str(tz_name),
            "expires_in": self.expires_in_str(),
            "days_remaining": self.days_remaining,
            "status": self.status,
            "issuer": self.issuer,
            "note": self.note,
            "error": self.error,
        }


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def days_between(not_after: datetime, now: datetime) -> int:
    """Whole days between ``not_after`` and ``now`` (floor division)."""
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    delta_seconds = (not_after - now).total_seconds()
    # Floor division so partial days round down (expired 12h ago -> -1).
    return int(delta_seconds // 86400)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def fetch_leaf_der(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """Open a TLS connection with SNI and return the leaf cert in DER form.

    Uses an unverified context *for fetching only* so expired / self-signed /
    mismatched certs are still returned. Never disables timeouts.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Tight, modern TLS floor without breaking old hosts.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:  # pragma: no cover - very old Pythons
        pass
    server_hostname = None if _is_ip(host) else host
    raw_sock: socket.socket | None = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        with ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            raw_sock = None  # owned by context manager now
            if not der:
                raise ssl.SSLError("No certificate returned by peer")
            if isinstance(der, bytes):
                return der
            return bytes(der)
    finally:
        if raw_sock is not None:
            try:
                raw_sock.close()
            except OSError:
                pass


def parse_der(der: bytes) -> tuple[datetime, datetime, str, object]:
    """Parse DER bytes with ``cryptography``.

    Returns ``(not_after_utc, not_before_utc, issuer_str, cert_object)``.
    """
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        # Python 3.9 / older cryptography: naive datetime assumed UTC.
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None)
    if not_before is None:  # pragma: no cover - compat path
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    issuer = cert.issuer.rfc4514_string()
    return (not_after, not_before, issuer, cert)


def _hostname_matches(cert: object, host: str) -> bool:
    """Check SAN/CN hostname match (incl. wildcard + IP SAN)."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID

        assert isinstance(cert, x509.Certificate)
        if _is_ip(host):
            try:
                ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                sans = ext.value.get_values_for_type(x509.IPAddress)
                needle = ipaddress.ip_address(host)
                return any(ip == needle for ip in sans)
            except Exception:
                return False
        # DNS SANs first.
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            dns_names = ext.value.get_values_for_type(x509.DNSName)
            if dns_names and _match_dns(dns_names, host):
                return True
            if dns_names:
                return False
        except Exception:
            pass  # fall through to CN
        # Fallback: Common Name.
        try:
            cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cns and _match_dns([c.value for c in cns], host):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def _match_dns(patterns: list[str], host: str) -> bool:
    host = host.lower().rstrip(".")
    for pat in patterns:
        pat = pat.lower().rstrip(".")
        if pat == host:
            return True
        if pat.startswith("*."):
            # Single-label wildcard per RFC 6125.
            suffix = pat[2:]
            if "." in host and host.split(".", 1)[1] == suffix:
                return True
    return False


def build_note(cert: object, host: str, not_after: datetime, now: datetime, not_before: datetime | None = None) -> str:
    """Describe validation problems: expired / self-signed / mismatch / not-yet-valid."""
    problems: list[str] = []
    try:
        if not_after < now:
            problems.append("expired")
        if not_before is not None and not_before > now:
            problems.append("not yet valid")
        try:
            if cert.issuer == cert.subject:  # type: ignore[attr-defined]
                problems.append("self-signed")
        except Exception:
            pass
        if not _hostname_matches(cert, host):
            problems.append("hostname mismatch")
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("Note build failed for %s: %s", host, exc)
    return "; ".join(problems)


def classify_error(exc: BaseException) -> str:
    """Map an exception to a user-facing error label."""
    if isinstance(exc, socket.gaierror):
        return f"DNS failure: {exc}"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return f"Connection timeout: {exc}"
    if isinstance(exc, ConnectionRefusedError):
        return f"Connection refused: {exc}"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"TLS handshake failure: {exc}"
    if isinstance(exc, ssl.SSLError):
        msg = str(exc).lower()
        if "certificate" in msg and "no certificate" in msg:
            return f"No certificate returned: {exc}"
        return f"TLS handshake failure: {exc}"
    if isinstance(exc, OSError):
        msg = str(exc).lower()
        if "refused" in msg:
            return f"Connection refused: {exc}"
        if "timed out" in msg or "timeout" in msg:
            return f"Connection timeout: {exc}"
        if "unreachable" in msg or "no route" in msg:
            return f"Connection failed (unreachable): {exc}"
        return f"Connection failed: {exc}"
    return f"Error: {exc}"


def check_one(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    now: datetime | None = None,
) -> CertResult:
    """Check a single domain. Never raises — one failure never stops the run."""
    current = now or utcnow()
    res = CertResult(domain=host, port=port, checked_at=current)
    try:
        der = fetch_leaf_der(host, port, timeout=timeout)
        not_after, not_before, issuer, cert = parse_der(der)
        res.expires_on = not_after
        res.days_remaining = days_between(not_after, current)
        res.issuer = issuer
        res.note = build_note(cert, host, not_after, current, not_before)
        res.success = True
    except Exception as exc:
        res.success = False
        res.error = classify_error(exc)
        log.debug("Check failed for %s:%s: %s", host, port, exc)
    return res


def check_domains(
    domains: list[tuple[str, int]],
    workers: int = DEFAULT_WORKERS,
    timeout: float = DEFAULT_TIMEOUT,
    now: datetime | None = None,
) -> list[CertResult]:
    """Check domains concurrently. Order of *completion*; caller sorts."""
    if not domains:
        return []
    workers = max(1, min(workers, len(domains)))
    current = now or utcnow()
    results: list[CertResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(check_one, host, port, timeout, current): (host, port)
            for host, port in domains
        }
        for fut in as_completed(future_map):
            try:
                results.append(fut.result())
            except Exception as exc:  # pragma: no cover - check_one never raises
                host, port = future_map[fut]
                r = CertResult(domain=host, port=port, checked_at=current)
                r.error = classify_error(exc)
                results.append(r)
    return results
