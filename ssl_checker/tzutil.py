"""Display timezone handling — Nepal Time by default.

All certificate timestamps are *stored* in UTC (ISO-8601); only the
*human-readable* rendering converts to the display zone so "expires in N
days" math never shifts with the wall clock.

Resolution order: explicit argument > ``display_timezone`` DB setting
(Settings page) > ``SSL_DISPLAY_TZ`` env var > ``Asia/Kathmandu``.

``zoneinfo`` is stdlib (Python 3.9+). If the host tz database is missing
a name, we fall back to a fixed UTC+5:45 offset for Kathmandu and to UTC
otherwise — the app never crashes on a bad timezone value.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache

log = logging.getLogger(__name__)

DEFAULT_TZ = "Asia/Kathmandu"
ENV_VAR = "SSL_DISPLAY_TZ"

#: Fixed-offset fallbacks when the system tz database lacks a zone.
_FIXED_OFFSETS = {
    "Asia/Kathmandu": timedelta(hours=5, minutes=45),  # NPT, no DST, ever
    "UTC": timedelta(0),
}

#: Human labels (tzdata has no "NPT" abbreviation — %Z yields "+0545").
_LABELS = {
    "Asia/Kathmandu": "NPT",
    "UTC": "UTC",
}


@lru_cache(maxsize=32)
def tzinfo_for(name: str):
    """Return a tzinfo for ``name`` (never raises)."""
    if not name:
        name = DEFAULT_TZ
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception as exc:
        log.debug("ZoneInfo(%r) unavailable: %s — using fixed offset", name, exc)
        if name in _FIXED_OFFSETS:
            return timezone(_FIXED_OFFSETS[name], name)
        return timezone.utc


def resolve_tz_name(explicit: str | None = None, db_path: str | None = None) -> str:
    """Resolve the effective display zone name (always a usable value)."""
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if db_path:
        try:
            from . import db as db_mod

            candidates.append(db_mod.get_setting(db_path, "display_timezone"))
        except Exception as exc:
            log.debug("DB timezone lookup failed: %s", exc)
    candidates.append(os.environ.get(ENV_VAR, "").strip())
    candidates.append(DEFAULT_TZ)
    for cand in candidates:
        if cand and _is_loadable(cand):
            return cand
    return DEFAULT_TZ


def _is_loadable(name: str) -> bool:
    if not name or name in _FIXED_OFFSETS:
        return bool(name)
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(name)
        return True
    except Exception:
        return False


def to_local(dt: datetime, tz_name: str | None = None):
    """Convert ``dt`` to the display zone (naive datetimes assumed UTC)."""
    zone = tzinfo_for(resolve_tz_name(tz_name))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(zone)


def fmt_local(dt: datetime, tz_name: str | None = None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """Format ``dt`` as ``YYYY-MM-DD HH:MM`` in the display zone."""
    return to_local(dt, tz_name).strftime(fmt)


def tz_label(tz_name: str | None = None) -> str:
    """Short label for headers, e.g. ``NPT`` / ``UTC`` / ``UTC+1``."""
    name = resolve_tz_name(tz_name)
    if name in _LABELS:
        return _LABELS[name]
    try:
        now = datetime.now(tzinfo_for(name))
        abbr = now.strftime("%Z")
        if abbr and not abbr.startswith(("+", "-")):
            return abbr
        offset = now.utcoffset() or timedelta(0)
        total_min = int(offset.total_seconds() // 60)
        sign = "+" if total_min >= 0 else "-"
        total_min = abs(total_min)
        return f"UTC{sign}{total_min // 60}:{total_min % 60:02d}"
    except Exception:
        return name
