"""Console / CSV / JSON / HTML rendering. No duplicated check logic."""
from __future__ import annotations

import csv
import html
import io
import json
import sys

from .checker import CertResult
from .evaluate import ERROR, sort_results

# ANSI colors — only used when stdout is a TTY and --no-color is not set.
_COLORS = {
    "EXPIRED": "\033[31m",  # red
    "CRITICAL": "\033[31m",
    "WARNING": "\033[33m",  # yellow
    "OK": "\033[32m",  # green
    "ERROR": "\033[35m",  # magenta
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


def _colorize(text: str, status: str, use_color: bool) -> str:
    if not use_color or status not in _COLORS:
        return text
    return f"{_COLORS[status]}{text}{_COLORS['RESET']}"


def summary_line(summary: dict[str, int]) -> str:
    return (
        f"Total: {summary.get('total', 0)} | OK: {summary.get('ok', 0)} | "
        f"Warning: {summary.get('warning', 0)} | "
        f"Critical: {summary.get('critical', 0)} | "
        f"Expired: {summary.get('expired', 0)} | "
        f"Failed: {summary.get('failed', 0)}"
    )


def render_table(
    results: list[CertResult], use_color: bool = False, tz_name: str | None = None
) -> str:
    """Render the console table (successes sorted, then Errors section)."""
    from . import tzutil as tz_mod

    good, bad = sort_results(results)
    label = tz_mod.tz_label(tz_name)
    headers = ["Domain", "Port", f"Expires On ({label})", "Expires In", "Status", "Issuer", "Note"]
    rows: list[list[str]] = []
    for r in good:
        rows.append(
            [
                r.domain,
                str(r.port),
                r.expires_str(tz_name),
                r.expires_in_str(),
                r.status,
                _truncate(r.issuer, 42),
                _truncate(r.note, 40),
            ]
        )
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    out = io.StringIO()
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out.write(sep + "\n")
    out.write("| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |\n")
    out.write(sep + "\n")
    for row, res in zip(rows, good):
        cells = []
        for i, cell in enumerate(row):
            padded = cell.ljust(widths[i])
            if i == 4:  # Status column
                padded = _colorize(padded, res.status, use_color)
            cells.append(padded)
        out.write("| " + " | ".join(cells) + " |\n")
    out.write(sep + "\n")
    if bad:
        out.write("\nErrors:\n")
        out.write(sep + "\n")
        out.write("| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |\n")
        out.write(sep + "\n")
        for r in bad:
            row = [
                r.domain,
                str(r.port),
                "—",
                "—",
                r.status,
                "",
                _truncate(r.error, 60),
            ]
            cells = []
            for i, cell in enumerate(row):
                padded = cell.ljust(widths[i])
                if i == 4:
                    padded = _colorize(padded, r.status, use_color)
                cells.append(padded)
            out.write("| " + " | ".join(cells) + " |\n")
        out.write(sep + "\n")
    return out.getvalue()


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def render_csv(results: list[CertResult]) -> str:
    from . import tzutil as tz_mod

    good, bad = sort_results(results)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["domain", "port", "expires_on_npt", "days_remaining", "status", "issuer", "note", "error"])
    for r in good + bad:
        writer.writerow(
            [
                r.domain,
                r.port,
                tz_mod.fmt_local(r.expires_on, "Asia/Kathmandu") if r.expires_on else "",
                r.days_remaining if r.days_remaining is not None else "",
                r.status,
                r.issuer,
                r.note,
                r.error,
            ]
        )
    return buf.getvalue()


def render_json(results: list[CertResult], summary: dict[str, int] | None = None) -> str:
    good, bad = sort_results(results)
    payload = {
        "results": [r.to_dict() for r in good + bad],
        "summary": summary if summary is not None else _auto_summary(results),
    }
    return json.dumps(payload, indent=2)


def _auto_summary(results: list[CertResult]) -> dict[str, int]:
    from .evaluate import summarize

    return summarize(results)


def render_html(
    results: list[CertResult],
    summary: dict[str, int] | None = None,
    title: str = "SSL Certificate Report",
    tz_name: str | None = None,
) -> str:
    """Standalone HTML report (inline CSS, escaped output)."""
    from . import tzutil as tz_mod
    from .evaluate import summarize as _sum

    good, bad = sort_results(results)
    summary = summary if summary is not None else _sum(results)
    label = tz_mod.tz_label(tz_name)
    esc = html.escape

    def badge(status: str) -> str:
        cls = status.lower()
        return f'<span class="badge {cls}">{esc(status)}</span>'

    rows = []
    for r in good:
        rows.append(
            "<tr>"
            f"<td>{esc(r.domain)}</td><td>{r.port}</td>"
            f"<td>{esc(r.expires_str(tz_name))}</td><td>{esc(r.expires_in_str())}</td>"
            f"<td>{badge(r.status)}</td><td>{esc(r.issuer)}</td><td>{esc(r.note)}</td>"
            "</tr>"
        )
    err_rows = []
    for r in bad:
        err_rows.append(
            "<tr>"
            f"<td>{esc(r.domain)}</td><td>{r.port}</td>"
            f"<td>—</td><td>—</td><td>{badge(r.status)}</td>"
            f"<td></td><td>{esc(r.error)}</td>"
            "</tr>"
        )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
body{{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;margin:24px;color:#1a202c;background:#f7fafc}}
.card{{background:#fff;border-radius:12px;padding:16px 20px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden}}
th,td{{padding:10px 12px;border-bottom:1px solid #e2e8f0;text-align:left;font-size:14px}}
tbody tr:nth-child(even){{background:#e9eff7}}
th{{background:#edf2f7;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.badge{{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700}}
.badge.ok{{background:#c6f6d5;color:#22543d}}.badge.warning{{background:#fefcbf;color:#744210}}
.badge.critical,.badge.expired{{background:#fed7d7;color:#9b2c2c}}.badge.error{{background:#e9d8fd;color:#553c9a}}
.summary{{display:flex;gap:12px;flex-wrap:wrap}}.stat{{flex:1;min-width:110px;text-align:center}}
.stat b{{display:block;font-size:22px}}
.footer{{margin:20px 4px 10px;text-align:center;color:#66748c;font-size:12px}}
.footer a{{color:#2456e6;font-weight:700;text-decoration:none}}
.footer a:hover{{text-decoration:underline}}
</style></head><body>
<h1>{esc(title)}</h1>
<p>All times Nepal Standard Time (UTC+05:45).</p>
<div class="card"><div class="summary">
<div class="stat"><b>{summary.get('total', 0)}</b>Total</div>
<div class="stat"><b>{summary.get('ok', 0)}</b>OK</div>
<div class="stat"><b>{summary.get('warning', 0)}</b>Warning</div>
<div class="stat"><b>{summary.get('critical', 0)}</b>Critical</div>
<div class="stat"><b>{summary.get('expired', 0)}</b>Expired</div>
<div class="stat"><b>{summary.get('failed', 0)}</b>Failed</div>
</div></div>
<div class="card"><h2>Certificates (soonest expiry first, times in {esc(label)})</h2>
<table><thead><tr><th>Domain</th><th>Port</th><th>Expires On ({esc(label)})</th><th>Expires In</th><th>Status</th><th>Issuer</th><th>Note</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="7">No successful checks.</td></tr>'}</tbody></table></div>
<div class="card"><h2>Errors</h2>
<table><thead><tr><th>Domain</th><th>Port</th><th>Expires On</th><th>Expires In</th><th>Status</th><th>Issuer</th><th>Error</th></tr></thead>
<tbody>{''.join(err_rows) if err_rows else '<tr><td colspan="7">No errors.</td></tr>'}</tbody></table></div>
<div class="footer">Powered by <a href="https://sagarmalla.info.np">Sagar Malla</a> · SSL Checker report</div>
</body></html>"""


def detect_color(no_color: bool) -> bool:
    """Colors only on a TTY unless --no-color is given."""
    if no_color:
        return False
    return sys.stdout.isatty()


def write_output(content: str, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    else:
        print(content, end="" if content.endswith("\n") else "\n")
