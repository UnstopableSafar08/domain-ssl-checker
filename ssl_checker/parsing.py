"""Domain input parsing.

Accepted line formats:
  - ``example.com``
  - ``example.com:8443``
  - ``https://example.com`` (scheme + path stripped)
  - ``https://example.com:8443/path?q=1``

Rules: ignore blank lines and lines starting with ``#``,
trim whitespace, lowercase, remove duplicates (order-preserving).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_HOST_RE = re.compile(r"^[a-z0-9._\-*\[\]:]+$")
DEFAULT_PORT = 443
MAX_DOMAINS = 500


def parse_domain_line(line: str) -> tuple[str, int] | None:
    """Parse a single input line into ``(host, port)``.

    Returns ``None`` for blank lines, comments, or invalid entries.
    """
    if line is None:
        return None
    s = line.strip().lower()
    if not s or s.startswith("#"):
        return None
    # Strip inline comments? No — '#' only counts at line start per spec.
    try:
        if "://" in s:
            parsed = urlparse(s)
            host = (parsed.hostname or "").strip().lower()
            if not host:
                log.debug("Unparsable line (no hostname): %r", line)
                return None
            port = parsed.port or DEFAULT_PORT
            if not 1 <= port <= 65535:
                return None
            if not _valid_host(host):
                return None
            return (host, port)
        # No scheme: strip path / query / fragment.
        s = s.split("#", 1)[0].strip()
        for sep in ("/", "?", "#"):
            if sep in s:
                s = s.split(sep, 1)[0].strip()
        if not s:
            return None
        # IPv6 literal e.g. [::1] or [::1]:8443
        if s.startswith("["):
            end = s.find("]")
            if end == -1:
                return None
            host = s[1:end].strip().lower()
            rest = s[end + 1 :].strip()
            port = DEFAULT_PORT
            if rest:
                if not rest.startswith(":"):
                    return None
                port_str = rest[1:]
                if not port_str.isdigit():
                    return None
                port = int(port_str)
                if not 1 <= port <= 65535:
                    return None
            if not _valid_host(host, allow_ipv6=True):
                return None
            return (host, port)
        # host[:port]
        if ":" in s:
            # Reject ambiguous multi-colon without brackets (likely bad IPv6).
            if s.count(":") > 1:
                return None
            host_part, _, port_str = s.rpartition(":")
            host_part = host_part.strip()
            port_str = port_str.strip()
            if not host_part or not port_str.isdigit():
                return None
            port = int(port_str)
            if not 1 <= port <= 65535:
                return None
            if not _valid_host(host_part):
                return None
            return (host_part, port)
        if not _valid_host(s):
            return None
        return (s, DEFAULT_PORT)
    except (ValueError, OverflowError) as exc:
        log.debug("Unparsable line %r: %s", line, exc)
        return None


def _valid_host(host: str, allow_ipv6: bool = False) -> bool:
    """Lightweight hostname / IP sanity check (deep validation happens at connect)."""
    if not host or len(host) > 253 or " " in host or "\t" in host:
        return False
    if not _HOST_RE.match(host) and not allow_ipv6:
        # Allow plain IPv4 + hostnames; be permissive so checker reports DNS errors.
        if not re.match(r"^[a-z0-9.\-]+$", host):
            return False
    if host.startswith("-") or host.startswith(".") or host.endswith("."):
        # Trailing dot (FQDN root) is tolerated — strip it.
        pass
    if ".." in host:
        return False
    return True


def dedupe(domains: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Remove duplicates, preserving first-seen order."""
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for item in domains:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_lines(lines: list[str]) -> list[tuple[str, int]]:
    """Parse an iterable of raw lines into a deduped ``[(host, port)]`` list."""
    parsed: list[tuple[str, int]] = []
    for line in lines:
        item = parse_domain_line(line)
        if item is not None:
            parsed.append(item)
    return dedupe(parsed)


def parse_text(text: str) -> list[tuple[str, int]]:
    """Parse textarea / pasted text (newline or comma separated)."""
    if not text:
        return []
    # Accept commas as separators too (common paste from spreadsheets).
    normalized = text.replace(",", "\n")
    return parse_lines(normalized.splitlines())


def parse_file(path: str | Path) -> list[tuple[str, int]]:
    """Parse a domains file from disk."""
    p = Path(path)
    content = p.read_text(encoding="utf-8", errors="replace")
    return parse_text(content)


def validate_count(domains: list[tuple[str, int]], limit: int = MAX_DOMAINS) -> None:
    """Raise ``ValueError`` if domain count exceeds the allowed limit."""
    if len(domains) > limit:
        raise ValueError(f"Too many domains: {len(domains)} > limit of {limit}")
    if not domains:
        raise ValueError("No valid domains found in input")
