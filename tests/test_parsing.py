"""Tests: input parsing. No network."""
from __future__ import annotations

from ssl_checker.parsing import dedupe, parse_domain_line, parse_lines, parse_text


def test_basic_host():
    assert parse_domain_line("Example.COM ") == ("example.com", 443)


def test_host_port():
    assert parse_domain_line("example.com:8443") == ("example.com", 8443)


def test_scheme_and_path_stripped():
    assert parse_domain_line("https://Example.com:8443/some/path?q=1") == ("example.com", 8443)
    assert parse_domain_line("https://example.com") == ("example.com", 443)
    assert parse_domain_line("http://example.com/") == ("example.com", 443)


def test_comments_and_blanks_ignored():
    assert parse_domain_line("") is None
    assert parse_domain_line("   ") is None
    assert parse_domain_line("# comment") is None
    assert parse_domain_line("  # comment") is None


def test_lowercase_trim_dedupe():
    assert parse_lines(["a.com", "A.COM", "a.com:443"]) == [("a.com", 443)]


def test_dedupe_order():
    assert dedupe([("b.com", 443), ("a.com", 443), ("b.com", 443)]) == [
        ("b.com", 443),
        ("a.com", 443),
    ]


def test_invalid_lines():
    assert parse_domain_line("https://") is None
    assert parse_domain_line("example.com:notaport") is None
    assert parse_domain_line("example.com:99999") is None
    assert parse_domain_line("a b.com") is None


def test_comma_separated_text():
    out = parse_text("a.com, b.com\nc.com")
    assert ("a.com", 443) in out and ("b.com", 443) in out and ("c.com", 443) in out


def test_trailing_path_without_scheme():
    assert parse_domain_line("example.com/some/path") == ("example.com", 443)
