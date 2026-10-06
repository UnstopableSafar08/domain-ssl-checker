"""Microsoft Teams webhook notifications.

- Webhook URL from ``TEAMS_WEBHOOK_URL`` (or ``--teams-webhook-env`` custom name).
  Never hardcoded, never printed, masked in logs.
- Adaptive Card by default; legacy MessageCard via ``--teams-format messagecard``.
- 10s timeout, 3 retries with exponential backoff; 429/5xx retried.
  Non-2xx = failure (logged, does not change cert-check exit code).
- Card capped at top 25 affected domains + "and N more" (Teams ~28KB limit).
- Reminder cadence via local JSON state file + ``--remind-every 24h``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .checker import CertResult
from .evaluate import sort_results, worst_severity

log = logging.getLogger(__name__)

MAX_CARD_DOMAINS = 25
TEAMS_TIMEOUT = 10.0
MAX_RETRIES = 3

_SEVERITY_META = {
    "EXPIRED": {"icon": "🔴", "color": "Attention", "title": "SSL certificates EXPIRED"},
    "CRITICAL": {"icon": "🟠", "color": "Attention", "title": "SSL certificates CRITICAL"},
    "WARNING": {"icon": "🟡", "color": "Warning", "title": "SSL certificates WARNING"},
    "OK": {"icon": "🟢", "color": "Good", "title": "SSL certificates OK"},
}


def get_webhook_url(env_name: str = "TEAMS_WEBHOOK_URL") -> str | None:
    """Read the webhook URL from the environment (never hardcoded)."""
    value = os.environ.get(env_name, "").strip()
    return value or None


def mask_url(url: str) -> str:
    """Mask a webhook URL for safe logging (never print the secret)."""
    if not url:
        return "(unset)"
    if len(url) <= 12:
        return "***"
    return f"{url[:8]}***{url[-4:]}"


def affected_sorted(results: list[CertResult]) -> list[CertResult]:
    """Affected = expired/critical/warning/failed, soonest expiry first, cap 25."""
    good, bad = sort_results(results)
    affected = [r for r in good if r.status in ("EXPIRED", "CRITICAL", "WARNING")]
    # bad (ERROR) sorted by domain already; append after cert problems.
    affected.extend(bad)
    return affected


def build_adaptive_card(
    results: list[CertResult],
    summary: dict[str, int],
    ui_url: str | None = None,
    checked_at: datetime | None = None,
    tz_name: str | None = None,
) -> dict:
    """Build an Adaptive Card payload (Power Automate / Workflows compatible)."""
    from . import tzutil as tz_mod

    worst = worst_severity(summary)
    meta = _SEVERITY_META.get(worst, _SEVERITY_META["WARNING"])
    checked_at = checked_at or datetime.now(timezone.utc)
    label = tz_mod.tz_label(tz_name)
    affected = affected_sorted(results)
    total_affected = len(affected)
    shown = affected[:MAX_CARD_DOMAINS]
    remaining = total_affected - len(shown)

    facts = [
        {"title": "Expired", "value": str(summary.get("expired", 0))},
        {"title": "Critical", "value": str(summary.get("critical", 0))},
        {"title": "Warning", "value": str(summary.get("warning", 0))},
        {"title": "Failed", "value": str(summary.get("failed", 0))},
        {"title": "OK", "value": str(summary.get("ok", 0))},
        {"title": "Total", "value": str(summary.get("total", 0))},
    ]

    rows: list[dict] = [
        {
            "type": "ColumnSet",
            "columns": [
                {"type": "Column", "width": "stretch", "items": [{"type": "TextBlock", "text": "Domain", "weight": "Bolder", "size": "Small"}]},
                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": f"Expiry ({label})", "weight": "Bolder", "size": "Small"}]},
                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": "Days left", "weight": "Bolder", "size": "Small"}]},
            ],
            "separator": True,
        }
    ]
    for r in shown:
        if r.success:
            days = str(r.days_remaining) if r.days_remaining is not None else "?"
            expiry = r.expires_str(tz_name)
        else:
            days = "error"
            expiry = r.error[:60] if r.error else "failed"
        rows.append(
            {
                "type": "ColumnSet",
                "columns": [
                    {"type": "Column", "width": "stretch", "items": [{"type": "TextBlock", "text": f"{r.domain}:{r.port} ({r.status})", "size": "Small", "wrap": True}]},
                    {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": expiry, "size": "Small"}]},
                    {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": days, "size": "Small"}]},
                ],
            }
        )
    if remaining > 0:
        rows.append(
            {"type": "TextBlock", "text": f"…and {remaining} more", "isSubtle": True, "size": "Small"}
        )
    if not shown:
        rows.append({"type": "TextBlock", "text": "All certificates are OK.", "size": "Small"})

    body: list[dict] = [
        {"type": "TextBlock", "text": f"{meta['icon']} {meta['title']}", "weight": "Bolder", "size": "Medium"},
        {"type": "FactSet", "facts": facts},
        {"type": "TextBlock", "text": f"Checked at {tz_mod.fmt_local(checked_at, tz_name)} {label}", "isSubtle": True, "size": "Small"},
        *rows,
    ]
    if ui_url:
        body.append(
            {
                "type": "ActionSet",
                "actions": [{"type": "Action.OpenUrl", "title": "Open SSL Checker UI", "url": ui_url}],
            }
        )
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


def build_messagecard(
    results: list[CertResult],
    summary: dict[str, int],
    ui_url: str | None = None,
    checked_at: datetime | None = None,
    tz_name: str | None = None,
) -> dict:
    """Build a legacy MessageCard payload (``--teams-format messagecard``)."""
    from . import tzutil as tz_mod

    worst = worst_severity(summary)
    meta = _SEVERITY_META.get(worst, _SEVERITY_META["WARNING"])
    checked_at = checked_at or datetime.now(timezone.utc)
    label = tz_mod.tz_label(tz_name)
    affected = affected_sorted(results)
    total_affected = len(affected)
    shown = affected[:MAX_CARD_DOMAINS]
    remaining = total_affected - len(shown)
    color = {"EXPIRED": "FF0000", "CRITICAL": "FF6A00", "WARNING": "FFC000", "OK": "00B050"}.get(worst, "0076D7")
    facts = [
        {"name": "Expired", "value": str(summary.get("expired", 0))},
        {"name": "Critical", "value": str(summary.get("critical", 0))},
        {"name": "Warning", "value": str(summary.get("warning", 0))},
        {"name": "Failed", "value": str(summary.get("failed", 0))},
        {"name": f"Checked ({label})", "value": tz_mod.fmt_local(checked_at, tz_name)},
    ]
    text_lines = []
    for r in shown:
        if r.success:
            text_lines.append(f"- **{r.domain}:{r.port}** — {r.expires_str(tz_name)} {label} ({r.expires_in_str()}, {r.status})")
        else:
            text_lines.append(f"- **{r.domain}:{r.port}** — ERROR: {r.error[:100]}")
    if remaining > 0:
        text_lines.append(f"…and {remaining} more")
    sections: list[dict] = [{"facts": facts, "text": "\n\n".join(text_lines) if text_lines else "All certificates are OK."}]
    card: dict = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"{meta['icon']} {meta['title']}",
        "title": f"{meta['icon']} {meta['title']}",
        "sections": sections,
    }
    if ui_url:
        card["potentialAction"] = [
            {"@type": "OpenUri", "name": "Open SSL Checker UI", "targets": [{"os": "default", "uri": ui_url}]}
        ]
    return card


def build_payload(
    results: list[CertResult],
    summary: dict[str, int],
    fmt: str = "adaptive",
    ui_url: str | None = None,
    checked_at: datetime | None = None,
    tz_name: str | None = None,
) -> dict:
    fmt = (fmt or "adaptive").lower()
    if fmt == "messagecard":
        return build_messagecard(results, summary, ui_url, checked_at, tz_name)
    return build_adaptive_card(results, summary, ui_url, checked_at, tz_name)


def build_test_card(
    ui_url: str | None = None,
    checked_at: datetime | None = None,
    tz_name: str | None = None,
) -> dict:
    """Tiny Adaptive Card used by the Settings page "Send test" button."""
    from . import tzutil as tz_mod

    checked_at = checked_at or datetime.now(timezone.utc)
    label = tz_mod.tz_label(tz_name)
    body: list[dict] = [
        {"type": "TextBlock", "text": "🔧 SSL Checker — test notification", "weight": "Bolder", "size": "Medium"},
        {"type": "TextBlock", "text": "If you can read this, the Teams webhook is wired up correctly.", "wrap": True},
        {"type": "TextBlock", "text": f"Sent at {tz_mod.fmt_local(checked_at, tz_name)} {label}", "isSubtle": True, "size": "Small"},
    ]
    if ui_url:
        body.append(
            {
                "type": "ActionSet",
                "actions": [{"type": "Action.OpenUrl", "title": "Open SSL Checker UI", "url": ui_url}],
            }
        )
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


def parse_duration(text: str) -> float:
    """Parse ``24h`` / ``30m`` / ``1d`` / seconds-int into seconds (float)."""
    text = (text or "").strip().lower()
    if re.fullmatch(r"\d+(\.\d+)?", text):
        return float(text)
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd])", text)
    if not m:
        raise ValueError(f"Invalid duration: {text!r} (examples: 24h, 30m, 1d, 3600)")
    value, unit = float(m.group(1)), m.group(2)
    return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def _load_state(path: str | None) -> dict:
    if not path:
        return {}
    try:
        p = Path(path)
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not read state file %s: %s", path, exc)
        return {}


def _save_state(path: str | None, state: dict) -> None:
    if not path:
        return
    try:
        Path(path).write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception as exc:
        log.warning("Could not write state file %s: %s", path, exc)


def should_send_with_state(
    results: list[CertResult],
    state_path: str | None,
    remind_every: str = "24h",
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Reminder cadence: re-notify only when a status changes or daily reminder elapses.

    Returns ``(should_send, reason)``. When no state file is configured,
    always returns ``(True, "no-state-file")`` — the caller still applies
    ``--notify-on`` rules first.
    """
    if not state_path:
        return True, "no-state-file"
    current = now or datetime.now(timezone.utc)
    remind_seconds = parse_duration(remind_every)
    state = _load_state(state_path)
    last_statuses: dict = state.get("statuses", {})
    last_notify_ts: float = float(state.get("last_notify_ts", 0) or 0)
    changed = False
    current_statuses: dict[str, str] = {}
    for r in results:
        key = f"{r.domain}:{r.port}"
        current_statuses[key] = r.status
        if last_statuses.get(key) != r.status:
            changed = True
    elapsed = current.timestamp() - last_notify_ts if last_notify_ts else float("inf")
    if changed:
        return True, "status-changed"
    if elapsed >= remind_seconds:
        return True, "reminder-due"
    return False, f"no-change; next reminder in {int(remind_seconds - elapsed)}s"


def record_notify(state_path: str | None, results: list[CertResult], now: datetime | None = None) -> None:
    if not state_path:
        return
    current = now or datetime.now(timezone.utc)
    _save_state(
        state_path,
        {
            "last_notify_ts": current.timestamp(),
            "last_notify_iso": current.astimezone(timezone.utc).isoformat(),
            "statuses": {f"{r.domain}:{r.port}": r.status for r in results},
        },
    )


def send_payload(
    webhook_url: str,
    payload: dict,
    timeout: float = TEAMS_TIMEOUT,
    max_retries: int = MAX_RETRIES,
) -> tuple[bool, str]:
    """POST the payload with 10s timeout + 3 retries (exp backoff on 429/5xx).

    Returns ``(ok, message)``. Never logs the URL itself (masked only).
    """
    import requests

    last_error = ""
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(webhook_url, json=payload, timeout=timeout)
            if 200 <= resp.status_code < 300:
                return True, f"Teams webhook accepted (HTTP {resp.status_code})"
            last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                wait = 2 ** (attempt - 1)
                log.warning(
                    "Teams webhook %s (attempt %d/%d); retrying in %ds",
                    last_error,
                    attempt,
                    max_retries,
                    wait,
                )
                time.sleep(wait)
                continue
            return False, f"Teams webhook rejected: {last_error}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            log.warning("Teams webhook error (attempt %d/%d): %s", attempt, max_retries, last_error)
            if attempt < max_retries:
                time.sleep(2 ** (attempt - 1))
    return False, f"Teams webhook failed after {max_retries} attempts: {last_error}"


def notify(
    results: list[CertResult],
    summary: dict[str, int],
    webhook_env: str = "TEAMS_WEBHOOK_URL",
    fmt: str = "adaptive",
    notify_on: str = "warning",
    ui_url: str | None = None,
    dry_run: bool = False,
    state_file: str | None = None,
    remind_every: str = "24h",
    tz_name: str | None = None,
) -> tuple[bool, str]:
    """High-level notify: apply rules, build payload, send (or dry-run).

    A Teams failure never raises — it returns ``(False, reason)`` so the
    certificate check exit code is unchanged.
    """
    from .evaluate import should_notify

    if not should_notify(summary, notify_on):
        return True, "Skipped: all certificates OK (notify-on=%s)" % notify_on
    if state_file and not dry_run:
        send_ok, reason = should_send_with_state(results, state_file, remind_every)
        if not send_ok:
            return True, f"Skipped: {reason}"
    payload = build_payload(results, summary, fmt, ui_url, tz_name=tz_name)
    if dry_run:
        return True, json.dumps(payload, indent=2)
    url = get_webhook_url(webhook_env)
    if not url:
        return False, f"Teams webhook env var {webhook_env} is not set"
    log.info("Sending Teams notification via %s (masked: %s)", webhook_env, mask_url(url))
    ok, msg = send_payload(url, payload)
    if ok and state_file:
        record_notify(state_file, results)
    return ok, msg
