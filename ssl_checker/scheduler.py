"""Background scheduler: re-check every domain every 5 minutes (configurable).

Alert cadence for expiry (per domain, per certificate):
- ``30d`` — sent ONCE when ``16 <= days_remaining <= 30``.
- ``15d`` — sent ONCE when ``days_remaining == 15``.
- ``daily`` — sent at most ONCE PER local DAY (display zone) when
  ``days_remaining <= 14`` (covers 14…1, expires-today and expired).
- ``error-daily`` — at most once per day while a domain keeps failing
  (DNS/timeout/refused/TLS), so outages are noticed without spam.

One-shot milestones are keyed by certificate (``expires_on``), so a
renewal automatically re-arms them. Daily milestones are keyed by
``(domain, cert, milestone, utc_date)``. All state lives in the
``alerts`` table — no fragile JSON sidecar files.

Due alerts across all domains are batched into a SINGLE Teams card per
cycle (top 25 + "and N more"), reusing the standard card builder.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from collections.abc import Callable

from . import db as db_mod
from .checker import CertResult

log = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 300  # 5 minutes


# ------------------------------------------------------- milestone rules ----
def milestone_for(days_remaining: int | None, success: bool) -> str | None:
    """Return the milestone key due for this result, or ``None``.

    Pure function of the check outcome — DB dedupe happens in
    :func:`run_cycle` via :func:`alert_slot`.
    """
    if not success or days_remaining is None:
        return "error-daily"
    if days_remaining > 30:
        return None
    if days_remaining >= 16:
        return "30d"
    if days_remaining == 15:
        return "15d"
    return "daily"  # 14…1, 0 (expires today) and expired (<0)


def alert_slot(milestone: str, now: datetime, tz_name: str | None = None) -> str:
    """Date component of the alert identity: ``''`` for one-shots, else local date.

    ``tz_name=None`` keeps the historical UTC behaviour; the scheduler passes
    the display zone so "daily" follows the local calendar day.
    """
    if milestone in ("30d", "15d"):
        return ""
    if tz_name is None:
        return now.astimezone(timezone.utc).strftime("%Y-%m-%d")
    from . import tzutil as tz_mod

    return tz_mod.to_local(now, tz_name).strftime("%Y-%m-%d")


def cert_key_for(result: CertResult) -> str:
    """Certificate identity: ``expires_on`` ISO, or ``''`` for failures."""
    if result.expires_on is None:
        return ""
    dt = result.expires_on
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


# ------------------------------------------------------------- DNS resolve ----
def _resolve_one(host: str, timeout: float = 1.5) -> str:
    """Resolve one host to a comma-joined, de-duplicated IP list (``''`` on failure).

    ``getaddrinfo`` has no timeout of its own, so it runs in a one-off thread;
    a stalled system resolver can delay this host at most ``timeout`` seconds.
    Literal IPs pass through untouched.
    """
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return ""
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="ssl-dns-one") as pool:
        fut = pool.submit(
            socket.getaddrinfo, h, None,
            family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
        )
        try:
            infos = fut.result(timeout=timeout)
        except Exception:
            return ""
    seen: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ip = sockaddr[0] if sockaddr else ""
        if ip and ip not in seen:
            seen.append(ip)
    return ", ".join(seen)


def resolve_many(
    hosts: list[str],
    workers: int = 20,
    timeout: float = 1.5,
    max_wait: float = 45.0,
) -> dict[str, str]:
    """Resolve many hosts concurrently with an overall deadline.

    Never raises and never blocks past ``max_wait``: stragglers are abandoned
    (their IPs stay ``''`` for this cycle and are retried next cycle).
    """
    unique: list[str] = []
    for h in hosts:
        if h not in unique:
            unique.append(h)
    out: dict[str, str] = {h: "" for h in unique}
    if not unique:
        return out
    n = max(1, min(workers, len(unique)))
    batches = (len(unique) + n - 1) // n
    deadline = min(max_wait, timeout * batches + 2.0)
    pool = ThreadPoolExecutor(max_workers=n, thread_name_prefix="ssl-dns")
    try:
        futs = {pool.submit(_resolve_one, h, timeout): h for h in unique}
        try:
            for fut in as_completed(futs, timeout=deadline):
                try:
                    out[futs[fut]] = fut.result()
                except Exception:
                    out[futs[fut]] = ""
        except TimeoutError:
            log.warning(
                "DNS resolve hit the %.0fs deadline (%d hosts); stragglers retry next cycle",
                deadline, len(unique),
            )
    finally:
        # Don't wait: running lookups keep their own threads until the OS
        # resolver gives up; pending ones are cancelled outright.
        pool.shutdown(wait=False, cancel_futures=True)
    return out


# ------------------------------------------------------------- scheduler ----
class Scheduler:
    """Daemon-thread scheduler. Safe to start/stop multiple times."""

    def __init__(
        self,
        db_path: str,
        *,
        interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
        allow_private: bool = False,
        workers: int = 20,
        timeout: float = 5.0,
        teams_env: str = "TEAMS_WEBHOOK_URL",
        teams_format: str = "adaptive",
        ui_url: str | None = None,
        on_alert: Callable[[dict, list[CertResult]], None] | None = None,
    ) -> None:
        self.db_path = db_path
        self.interval_seconds = max(30, int(interval_seconds))
        self.allow_private = allow_private
        self.workers = workers
        self.timeout = timeout
        self.teams_env = teams_env
        self.teams_format = teams_format
        self.ui_url = ui_url
        self.on_alert = on_alert  # test / observability hook
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_run_at: str | None = None
        self.last_summary: dict | None = None
        self.last_error: str | None = None
        self._lock = threading.Lock()
        # Manual/background cycle coordination: at most one cycle at a time
        # so a slow 400-domain check never stacks, and the loop never
        # double-sends milestone alerts alongside a manual run.
        self._cycle_lock = threading.Lock()
        self._cycle_running = False
        self._cycle_started_at: str | None = None

    # -- lifecycle ------------------------------------------------------
    def start(self, run_immediately: bool = True) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, kwargs={"run_immediately": run_immediately},
            name="ssl-scheduler", daemon=True,
        )
        self._thread.start()
        log.info("Scheduler started (every %ds, db=%s)", self.interval_seconds, self.db_path)

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None
        log.info("Scheduler stopped")

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict:
        try:
            effective = self.effective_config()
        except Exception as exc:
            effective = {"error": str(exc)}
        with self._cycle_lock:
            cycle_running = self._cycle_running
            cycle_started_at = self._cycle_started_at
        with self._lock:
            return {
                "running": self.running,
                "interval_seconds": self.interval_seconds,
                "last_run_at": self.last_run_at,
                "last_summary": self.last_summary,
                "last_error": self.last_error,
                "cycle_running": cycle_running,
                "cycle_started_at": cycle_started_at,
                "db_path": self.db_path,
                "effective": effective,
            }

    # -- live settings (Settings page > env > constructor default) --------
    def _eff(self, key: str, fallback: str) -> str:
        try:
            return db_mod.get_setting(self.db_path, key)
        except Exception:
            return fallback

    @staticmethod
    def _as_bool(value: str) -> bool:
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    def _current_interval(self) -> int:
        try:
            return max(30, int(float(self._eff("check_interval_seconds", str(self.interval_seconds)))))
        except (TypeError, ValueError):
            return max(30, self.interval_seconds)

    def effective_config(self) -> dict:
        """Resolved runtime config + where the webhook comes from (secret never included)."""
        import os as _os

        from . import tzutil as tz_mod

        url, source = self._resolve_webhook()
        try:
            workers = max(1, min(int(float(self._eff("check_workers", str(self.workers)))), 100))
        except (TypeError, ValueError):
            workers = self.workers
        try:
            timeout = float(self._eff("check_timeout_seconds", str(self.timeout)))
        except (TypeError, ValueError):
            timeout = self.timeout
        return {
            "interval_seconds": self._current_interval(),
            "workers": workers,
            "timeout": timeout,
            "teams_format": self._eff("teams_format", self.teams_format),
            "ui_url": self._eff("ui_url", self.ui_url or _os.environ.get("SSL_UI_URL", "") or ""),
            "allow_private": self._as_bool(
                self._eff("allow_private", "1" if self.allow_private else "0")
            ),
            "notifications_enabled": self._as_bool(self._eff("notifications_enabled", "1")),
            "display_timezone": tz_mod.resolve_tz_name(
                self._eff("display_timezone", tz_mod.DEFAULT_TZ)
            ),
            "webhook_configured": bool(url),
            "webhook_source": source,
        }

    def _resolve_webhook(self) -> tuple[str | None, str]:
        """Webhook URL + source (``db`` | ``env`` | ``unset``). Secret stays in memory only."""
        import os as _os

        try:
            with db_mod.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key='teams_webhook_url'"
                ).fetchone()
                db_url = (row["value"] if row else "") or ""
                if db_url.strip():
                    return db_url.strip(), "db"
        except Exception as exc:
            log.debug("Webhook DB lookup failed: %s", exc)
        env_url = (_os.environ.get(self.teams_env, "") or "").strip()
        if env_url:
            return env_url, "env"
        return None, "unset"

    def _loop(self, run_immediately: bool) -> None:
        if run_immediately and self._begin_cycle():
            # Guarded: one bad first cycle must never kill the loop thread.
            self._run_cycle_guarded()
        while not self._stop.wait(self._current_interval()):
            if not self._begin_cycle():
                log.info("Skipping scheduled cycle: another check is still running")
                continue
            self._run_cycle_guarded()

    # -- manual / background cycles (never block the caller) ----------------
    @property
    def cycle_running(self) -> bool:
        with self._cycle_lock:
            return self._cycle_running

    def _begin_cycle(self) -> bool:
        """Claim the single cycle slot. Returns False if one is in progress."""
        with self._cycle_lock:
            if self._cycle_running:
                return False
            self._cycle_running = True
            self._cycle_started_at = datetime.now(timezone.utc).isoformat()
            return True

    def _end_cycle(self) -> None:
        with self._cycle_lock:
            self._cycle_running = False
            self._cycle_started_at = None

    def _run_cycle_guarded(self) -> None:
        """Run one cycle; a failure is recorded, never raised."""
        try:
            self.run_cycle()
        except Exception as exc:  # never kill the loop / background thread
            log.exception("Check cycle failed: %s", exc)
            with self._lock:
                self.last_error = str(exc)
        finally:
            self._end_cycle()

    def trigger_cycle(self) -> tuple[bool, str]:
        """Start one cycle in a background daemon thread. Never blocks.

        Returns ``(started, message)`` — ``started`` is False when a cycle
        (manual or scheduled) is already running.
        """
        if not self._begin_cycle():
            return False, "A check cycle is already running — watching it finish instead of stacking another."
        threading.Thread(target=self._run_cycle_guarded, name="ssl-check-now", daemon=True).start()
        return True, "Check cycle started in background; progress shows in Monitored domains."

    # -- one cycle -------------------------------------------------------
    def run_cycle(self, now: datetime | None = None) -> dict:
        """Check all enabled domains, persist, and fire due milestone alerts."""
        from . import checker as checker_mod
        from . import evaluate as eval_mod
        from . import notify_teams as teams_mod

        current = now or datetime.now(timezone.utc)
        started = time.monotonic()
        t0 = datetime.now(timezone.utc)
        cfg = self.effective_config()

        domains = db_mod.list_domains(self.db_path, only_enabled=True)
        summary: dict = {
            "checked": 0, "ok": 0, "alerts_due": 0, "alerts_sent": False,
            "detail": "", "started_at": t0.isoformat(),
        }
        if not domains:
            summary["detail"] = "No enabled domains in DB"
            self._remember(summary, t0)
            return summary

        # SSRF guard (same policy as the web UI).
        safe: list[tuple[str, int, int]] = []  # (host, port, domain_id)
        blocked: list[tuple[dict, CertResult]] = []
        for d in domains:
            host = d["domain"]
            if not cfg["allow_private"]:
                from .web import is_private_target  # lazy: avoids circular import

                private, detail = is_private_target(host)
                if private:
                    r = CertResult(domain=host, port=d["port"], checked_at=current)
                    r.success = False
                    r.status = "ERROR"
                    r.error = f"Blocked private/loopback target (SSRF protection): {detail}"
                    blocked.append((d, r))
                    continue
            safe.append((host, d["port"], d["id"]))

        results: list[CertResult] = []
        if safe:
            batch = checker_mod.check_domains(
                [(h, p) for h, p, _ in safe],
                workers=min(cfg["workers"], len(safe)),
                timeout=cfg["timeout"], now=current,
            )
            by_key = {(r.domain, r.port): r for r in batch}
            for host, port, _did in safe:
                results.append(by_key.get((host, port)) or checker_mod.check_one(host, port, cfg["timeout"], current))
        eval_mod.apply_status(results)
        for _d, r in blocked:
            results.append(r)

        # Persist every outcome (history + analytics).
        elapsed_ms = (time.monotonic() - started) * 1000.0
        avg_ms = round(elapsed_ms / max(len(results), 1), 2)
        id_by_key = {(d["domain"], d["port"]): d["id"] for d in domains}
        # Resolved IPs ride along with every check (bounded, never blocks past
        # its deadline; stragglers retry next cycle). Powers the IPs column.
        ip_map = resolve_many(sorted({r.domain for r in results}))
        for r in results:
            did = id_by_key.get((r.domain, r.port))
            if did is None:
                continue
            exp_iso = None
            if r.expires_on is not None:
                exp = r.expires_on
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                exp_iso = exp.astimezone(timezone.utc).isoformat()
            db_mod.record_check(
                self.db_path, did, success=r.success, expires_on=exp_iso,
                days_remaining=r.days_remaining, status=r.status, issuer=r.issuer,
                note=r.note, error=r.error, ips=ip_map.get(r.domain, ""),
                duration_ms=avg_ms,
                checked_at=(r.checked_at or current).isoformat(),
            )

        # Milestone dedupe → batch the newly-due alerts into one Teams card.
        due: list[tuple[dict, CertResult, str]] = []
        for r in results:
            did = id_by_key.get((r.domain, r.port))
            if did is None:
                continue
            milestone = milestone_for(r.days_remaining, r.success)
            if milestone is None:
                continue
            slot = alert_slot(milestone, current, tz_name=cfg["display_timezone"])
            if db_mod.has_alert(self.db_path, did, cert_key_for(r), milestone, slot):
                continue
            dom = next((d for d in domains if d["id"] == did), None)
            due.append((dom or {"id": did, "domain": r.domain, "port": r.port}, r, milestone))

        summary["checked"] = len(results)
        summary["alerts_due"] = len(due)
        if not due:
            summary["detail"] = "No milestone alerts due"
        elif not cfg["notifications_enabled"]:
            summary["detail"] = (
                f"{len(due)} alert(s) due but notifications are disabled in Settings"
            )
            log.info("Scheduler: %s", summary["detail"])
        else:
            due_results = [r for _, r, _ in due]
            fleet = eval_mod.summarize(results)
            payload = teams_mod.build_payload(
                due_results, fleet, cfg["teams_format"], cfg["ui_url"] or None, current,
                tz_name=cfg["display_timezone"],
            )
            url, source = self._resolve_webhook()
            if url is None:
                summary["detail"] = (
                    f"{len(due)} alert(s) due but no Teams webhook is set "
                    f"(Settings page or {self.teams_env})"
                )
                log.warning("Scheduler: %s", summary["detail"])
            else:
                log.info(
                    "Scheduler: sending Teams alert (webhook from %s, masked %s) for %d domain(s)",
                    source, teams_mod.mask_url(url), len(due),
                )
                ok, msg = teams_mod.send_payload(url, payload)
                summary["alerts_sent"] = ok
                summary["detail"] = msg
                if ok:
                    for dom, r, milestone in due:
                        db_mod.record_alert(
                            self.db_path, dom["id"], cert_key_for(r), milestone,
                            alert_date=alert_slot(milestone, current, tz_name=cfg["display_timezone"]),
                            days_remaining=r.days_remaining, status=r.status,
                            detail=f"days={r.days_remaining}",
                        )
                else:
                    log.error("Scheduler Teams send failed: %s", msg)
            if self.on_alert is not None:
                try:
                    self.on_alert(summary, due_results)
                except Exception:
                    log.exception("on_alert hook failed")

        fleet = eval_mod.summarize(results)
        summary.update({k: fleet[k] for k in ("ok", "warning", "critical", "expired", "failed")})
        self._remember(summary, t0)
        log.info(
            "Scheduled check: %d domain(s), ok=%d warn=%d crit=%d exp=%d fail=%d, alerts_due=%d",
            len(results), fleet.get("ok", 0), fleet.get("warning", 0),
            fleet.get("critical", 0), fleet.get("expired", 0),
            fleet.get("failed", 0), len(due),
        )
        return summary

    def _remember(self, summary: dict, t0: datetime) -> None:
        with self._lock:
            self.last_run_at = t0.astimezone(timezone.utc).isoformat()
            self.last_summary = summary
            self.last_error = None


def run_forever(
    db_path: str,
    *,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    **kwargs,
) -> int:
    """Blocking scheduler loop for the ``scheduler`` CLI command / containers."""
    sched = Scheduler(db_path, interval_seconds=interval_seconds, **kwargs)
    db_mod.init_db(db_path)
    sched.run_cycle()
    sched.start(run_immediately=False)
    log.info("Scheduler loop running every %ds — Ctrl+C to stop", sched.interval_seconds)
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Interrupted, shutting down scheduler")
    finally:
        sched.stop()
    return 0


def interval_from_env(default: int = DEFAULT_INTERVAL_SECONDS) -> int:
    try:
        return max(30, int(os.environ.get("SSL_CHECK_INTERVAL_SECONDS", default)))
    except (TypeError, ValueError):
        return default
