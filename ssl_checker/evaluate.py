"""Status classification, sorting, summaries, exit codes, notify decisions."""
from __future__ import annotations

from .checker import CertResult

EXPIRED = "EXPIRED"
CRITICAL = "CRITICAL"
WARNING = "WARNING"
OK = "OK"
ERROR = "ERROR"

DEFAULT_CRITICAL_DAYS = 7
DEFAULT_WARNING_DAYS = 30


def classify(
    days_remaining: int | None,
    success: bool,
    critical: int = DEFAULT_CRITICAL_DAYS,
    warning: int = DEFAULT_WARNING_DAYS,
) -> str:
    """Map days-remaining to EXPIRED / CRITICAL / WARNING / OK / ERROR."""
    if not success or days_remaining is None:
        return ERROR
    if days_remaining < 0:
        return EXPIRED
    if days_remaining <= critical:
        return CRITICAL
    if days_remaining <= warning:
        return WARNING
    return OK


def apply_status(
    results: list[CertResult],
    critical: int = DEFAULT_CRITICAL_DAYS,
    warning: int = DEFAULT_WARNING_DAYS,
) -> list[CertResult]:
    """Fill ``result.status`` in place and return the list."""
    for r in results:
        r.status = classify(r.days_remaining, r.success, critical, warning)
    return results


def sort_results(results: list[CertResult]) -> tuple[list[CertResult], list[CertResult]]:
    """Split into (ok_sorted, errors).

    Successes ascending by days remaining (expired first); ties by domain.
    Errors sorted by domain for stability.
    """
    good = [r for r in results if r.success]
    bad = [r for r in results if not r.success]
    good.sort(
        key=lambda r: (
            r.days_remaining if r.days_remaining is not None else 10**9,
            r.domain,
            r.port,
        )
    )
    bad.sort(key=lambda r: (r.domain, r.port))
    return good, bad


def summarize(results: list[CertResult]) -> dict[str, int]:
    """Count total / ok / warning / critical / expired / failed."""
    counts = {
        "total": len(results),
        "ok": 0,
        "warning": 0,
        "critical": 0,
        "expired": 0,
        "failed": 0,
    }
    for r in results:
        if not r.success:
            counts["failed"] += 1
        elif r.status == OK:
            counts["ok"] += 1
        elif r.status == WARNING:
            counts["warning"] += 1
        elif r.status == CRITICAL:
            counts["critical"] += 1
        elif r.status == EXPIRED:
            counts["expired"] += 1
        else:  # pragma: no cover - defensive
            counts["failed"] += 1
    return counts


def exit_code(summary: dict[str, int]) -> int:
    """0 all OK, 1 any WARNING, 2 any CRITICAL/EXPIRED/FAILED, 3 reserved for tool errors."""
    if summary.get("expired", 0) > 0 or summary.get("critical", 0) > 0:
        return 2
    if summary.get("failed", 0) > 0:
        # A domain that failed to connect needs attention — treat as critical.
        return 2
    if summary.get("warning", 0) > 0:
        return 1
    return 0


def worst_severity(summary: dict[str, int]) -> str:
    """Return the worst status present (for card color / title)."""
    if summary.get("expired", 0) > 0:
        return EXPIRED
    if summary.get("critical", 0) > 0 or summary.get("failed", 0) > 0:
        return CRITICAL
    if summary.get("warning", 0) > 0:
        return WARNING
    return OK


def should_notify(summary: dict[str, int], notify_on: str = "warning") -> bool:
    """Decide whether a Teams notification should be sent.

    - ``warning``: send when warning/critical/expired/failed > 0.
    - ``critical``: send when critical/expired/failed > 0.
    - ``always``: always send, even when all OK.
    """
    notify_on = (notify_on or "warning").lower()
    if notify_on == "always":
        return True
    if notify_on == "critical":
        return bool(
            summary.get("critical", 0)
            or summary.get("expired", 0)
            or summary.get("failed", 0)
        )
    # default: warning
    return bool(
        summary.get("warning", 0)
        or summary.get("critical", 0)
        or summary.get("expired", 0)
        or summary.get("failed", 0)
    )
