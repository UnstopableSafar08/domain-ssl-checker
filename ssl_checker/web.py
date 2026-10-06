"""Flask web UI (single page, offline assets + Lucide icons, no CDN)."""
from __future__ import annotations

import base64
import functools
import html
import ipaddress
import logging
import os
import secrets
import socket
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

MAX_DOMAINS = 500
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
TXT_ONLY_ERROR = "Only .txt files are accepted for upload"


def _check_txt_filename(filename: str | None) -> None:
    """Reject non-.txt uploads. Raises ``ValueError`` with a 400-level message."""
    if filename and not filename.lower().endswith(".txt"):
        raise ValueError(f"{TXT_ONLY_ERROR} (got {filename!r})")

# Offline vendored UI assets (Lucide icons, CSS, JS, fonts, images).
# Resolved as: <repo>/assets first, then <package>/assets (wheel installs).
_ASSETS_DIR: Path | None = next(
    (
        cand
        for cand in (
            Path(__file__).resolve().parent.parent / "assets",
            Path(__file__).resolve().parent / "assets",
        )
        if (cand / "css" / "app.css").exists()
    ),
    None,
)


def _assets_version() -> str:
    """Cache-buster for vendored assets: max mtime, so every deploy gets fresh URLs."""
    if _ASSETS_DIR is None:
        return "0"
    try:
        mtimes = [p.stat().st_mtime for p in _ASSETS_DIR.rglob("*") if p.is_file()]
        return str(int(max(mtimes))) if mtimes else "0"
    except Exception:
        return "0"


_ASSETS_VERSION = _assets_version()


def _get_secret_key() -> str:
    return os.environ.get("SSL_CHECKER_SECRET_KEY", secrets.token_hex(32))


def _get_auth() -> tuple[str | None, str | None]:
    user = os.environ.get("SSL_CHECKER_USER") or None
    password = os.environ.get("SSL_CHECKER_PASSWORD") or None
    if user and password:
        return user, password
    return None, None


def is_private_target(host: str) -> tuple[bool, str]:
    """Return (is_private, detail). DNS-resolves and inspects all addr infos.

    Any private / loopback / link-local / multicast / reserved / unspecified
    IP marks the target as private (SSRF protection).
    """
    host = (host or "").strip().strip("[]").lower()
    if not host:
        return True, "empty hostname"
    # Literal IP fast path.
    try:
        ip = ipaddress.ip_address(host)
        if _ip_is_blocked(ip):
            return True, str(ip)
        return False, str(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        # Unresolvable — not private; let the checker report DNS failure.
        return False, f"unresolvable ({exc})"
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0] if sockaddr else ""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            return True, str(ip)
    return False, "public"


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def create_app(
    default_file: str = "domains.txt",
    allow_private: bool = False,
    db_path: str | None = None,
    enable_scheduler: bool = True,
    check_interval: int = 300,
):
    from flask import Flask, jsonify, request, session

    from . import checker as checker_mod
    from . import db as db_mod
    from . import evaluate as eval_mod
    from . import notify_teams as teams_mod
    from . import parsing as parsing_mod
    from . import scheduler as sched_mod

    app = Flask(__name__)
    app.secret_key = _get_secret_key()
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["SSL_ALLOW_PRIVATE"] = allow_private
    app.config["SSL_DEFAULT_FILE"] = default_file

    # --- Persistent store + background 5-minute checker -------------------
    resolved_db = db_mod.init_db(db_mod.resolve_db_path(db_path))
    app.config["SSL_DB_PATH"] = resolved_db
    if default_file:
        try:
            # Seed once: only when the watch list is completely empty.
            if not db_mod.list_domains(resolved_db):
                db_mod.seed_from_file(resolved_db, default_file)
        except Exception as exc:
            log.warning("DB seed skipped: %s", exc)
    scheduler = sched_mod.Scheduler(
        resolved_db,
        interval_seconds=check_interval,
        allow_private=allow_private,
        ui_url=os.environ.get("SSL_UI_URL") or None,
        teams_env=os.environ.get("SSL_TEAMS_ENV", "TEAMS_WEBHOOK_URL"),
    )
    app.config["SSL_SCHEDULER"] = scheduler
    # Don't autostart under pytest / Flask testing (tests drive cycles manually).
    _under_pytest = bool(os.environ.get("PYTEST_CURRENT_TEST"))
    if enable_scheduler and not app.testing and not _under_pytest:
        scheduler.start(run_immediately=True)

    auth_user, auth_pass = _get_auth()

    def require_auth(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if not auth_user or not auth_pass:
                return view(*args, **kwargs)
            auth = request.authorization
            if auth and auth.username == auth_user and auth.password == auth_pass:
                return view(*args, **kwargs)
            return (
                jsonify({"error": "Authentication required"}),
                401,
                {"WWW-Authenticate": 'Basic realm="ssl-checker"'},
            )

        return wrapper

    def csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_hex(32)
            session["csrf_token"] = token
        return token

    def check_csrf() -> bool:
        expected = session.get("csrf_token", "")
        got = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
        return bool(expected) and secrets.compare_digest(str(got), str(expected))

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        return resp

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/assets/<path:filename>")
    def assets(filename: str):
        """Serve vendored offline UI assets (no auth: public CSS/JS/icons/fonts)."""
        from flask import send_from_directory

        if _ASSETS_DIR is None:
            return jsonify({"error": "Assets not found"}), 404
        resp = send_from_directory(str(_ASSETS_DIR), filename, max_age=3600)
        if filename.endswith((".js", ".css", ".woff2")):
            resp.headers["Cache-Control"] = "public, max-age=3600, immutable"
        return resp

    @app.get("/favicon.ico")
    @app.get("/favicon.svg")
    def favicon():
        """Quiet auto-requested favicon path (same file as the <link rel=icon>)."""
        from flask import send_from_directory

        if _ASSETS_DIR is None:
            return jsonify({"error": "Assets not found"}), 404
        return send_from_directory(str(_ASSETS_DIR / "img"), "favicon.svg", max_age=86400)

    @app.get("/")
    @require_auth
    def index():
        from . import tzutil as tz_mod

        token = csrf_token()
        authed = bool(auth_user and auth_pass)
        tz_name = tz_mod.resolve_tz_name(db_path=str(app.config["SSL_DB_PATH"]))
        page = _INDEX_HTML.replace("__CSRF_TOKEN__", html.escape(token))
        page = page.replace("__DISPLAY_TZ__", html.escape(tz_name))
        page = page.replace("__TZ_LABEL__", html.escape(tz_mod.tz_label(tz_name)))
        page = page.replace("__ASSETS_V__", _ASSETS_VERSION)
        return page.replace(
            "__AUTH_NOTE__", "Protected by basic auth." if authed else "Public mode (set SSL_CHECKER_USER/PASSWORD to protect)."
        )

    @app.get("/api/defaults")
    @require_auth
    def defaults():
        path = app.config["SSL_DEFAULT_FILE"]
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace") if Path(path).exists() else ""
        except Exception as exc:
            return jsonify({"error": f"Could not read default file: {exc}"}), 500
        domains = parsing_mod.parse_text(text)
        preview = [f"{h}:{p}" if p != 443 else h for h, p in domains[:MAX_DOMAINS]]
        return jsonify({"text": text[:50000], "count": len(domains), "preview": preview})

    def _extract_domains_from_request() -> tuple[list[tuple[str, int]], str]:
        """Support JSON {domains_text|domains[]} and multipart file upload."""
        ctype = request.content_type or ""
        if "multipart/form-data" in ctype:
            f = request.files.get("file")
            text_area = request.form.get("domains_text", "")
            parts: list[str] = [text_area or ""]
            if f and f.filename:
                _check_txt_filename(f.filename)
                data = f.read()
                if len(data) > MAX_UPLOAD_BYTES:
                    raise ValueError("Upload exceeds 5 MB limit")
                parts.append(data.decode("utf-8", errors="replace"))
            combined = "\n".join(parts)
            return parsing_mod.parse_text(combined), "upload+textarea"
        payload = request.get_json(silent=True) or {}
        if isinstance(payload.get("domains"), list):
            lines = [str(x) for x in payload["domains"]]
            return parsing_mod.parse_lines(lines), "json-list"
        text = str(payload.get("domains_text", "") or "")
        if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise ValueError("Input exceeds 5 MB limit")
        return parsing_mod.parse_text(text), "json-text"

    def _run_checks(domains: list[tuple[str, int]]):
        """Apply SSRF guard then concurrent TLS checks. Returns (results, blocked)."""
        from .checker import CertResult

        allow = bool(app.config["SSL_ALLOW_PRIVATE"])
        safe: list[tuple[str, int]] = []
        blocked: list[CertResult] = []
        now = datetime.now(timezone.utc)
        for host, port in domains:
            if not allow:
                private, detail = is_private_target(host)
                if private:
                    r = CertResult(domain=host, port=port, checked_at=now)
                    r.success = False
                    r.status = "ERROR"
                    r.error = f"Blocked private/loopback target (SSRF protection): {detail}. Retry with --allow-private for internal domains."
                    blocked.append(r)
                    continue
            safe.append((host, port))
        results = checker_mod.check_domains(safe, workers=min(20, max(1, len(safe))) if safe else 1)
        results.extend(blocked)
        eval_mod.apply_status(results)
        return results

    @app.post("/api/check")
    @require_auth
    def api_check():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        try:
            domains, _src = _extract_domains_from_request()
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 413 if "5 MB" in str(exc) else 400
        if not domains:
            return jsonify({"error": "No valid domains found in input"}), 400
        if len(domains) > MAX_DOMAINS:
            return jsonify({"error": f"Too many domains: {len(domains)} > limit of {MAX_DOMAINS}"}), 400
        results = _run_checks(domains)
        good, bad = eval_mod.sort_results(results)
        ordered = good + bad
        summary = eval_mod.summarize(results)
        checked_at = datetime.now(timezone.utc).isoformat()
        return jsonify(
            {
                "results": [r.to_dict() for r in ordered],
                "summary": summary,
                "checked_at": checked_at,
            }
        )

    @app.post("/api/notify")
    @require_auth
    def api_notify():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        payload = request.get_json(silent=True) or {}
        try:
            domains, _ = _extract_domains_from_request() if "domains_text" in payload or "domains" in payload else ([], "")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        # UI sends the already-checked snapshot? Prefer authoritative re-check
        # when domains are supplied; otherwise accept a results snapshot.
        fmt = str(payload.get("teams_format", "adaptive"))
        notify_on = str(payload.get("notify_on", "warning"))
        ui_url = payload.get("ui_url") or None
        dry_run = bool(payload.get("dry_run", False))
        webhook_env = str(payload.get("webhook_env", "TEAMS_WEBHOOK_URL"))
        if domains:
            if len(domains) > MAX_DOMAINS:
                return jsonify({"error": f"Too many domains: {len(domains)} > {MAX_DOMAINS}"}), 400
            results = _run_checks(domains)
        else:
            snap = payload.get("results") or []
            if not snap or len(snap) > MAX_DOMAINS:
                return jsonify({"error": "Provide domains_text/domains or a results snapshot (<=500)"}), 400
            results = _results_from_snapshot(snap)
        summary = eval_mod.summarize(results)
        from . import db as db_mod

        ok, msg = teams_mod.notify(
            results, summary, webhook_env=webhook_env, fmt=fmt,
            notify_on=notify_on, ui_url=ui_url, dry_run=dry_run,
            tz_name=db_mod.get_setting(_db(), "display_timezone"),
        )
        status = 200 if ok else 502
        out: dict = {"ok": ok, "message": msg, "summary": summary}
        if dry_run and ok and "Skipped" not in msg:
            import json as _json

            try:
                out["payload"] = _json.loads(msg)
            except Exception:
                out["payload_text"] = msg
        return jsonify(out), status

    # ------------------------- DB-backed watch list + analytics ----------
    def _db() -> str:
        from . import db as db_mod

        return str(app.config["SSL_DB_PATH"])

    @app.get("/api/scheduler")
    @require_auth
    def api_scheduler():
        sched: object = app.config.get("SSL_SCHEDULER")
        status = sched.status() if sched is not None else {"running": False}
        return jsonify(status)

    @app.post("/api/check-now")
    @require_auth
    def api_check_now():
        # Async by design: a 400-domain cycle takes minutes, far longer than
        # any browser / proxy / gunicorn patience. Trigger a background cycle
        # and let the UI poll /api/analytics (scheduler.cycle_running).
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        sched = app.config.get("SSL_SCHEDULER")
        if sched is None:
            return jsonify({"error": "Scheduler not configured"}), 500
        try:
            started, msg = sched.trigger_cycle()
        except Exception as exc:
            log.exception("Manual cycle trigger failed: %s", exc)
            return jsonify({"error": str(exc)}), 500
        return jsonify({"started": started, "message": msg, "status": sched.status()}), (202 if started else 200)

    @app.get("/api/domains")
    @require_auth
    def api_domains():
        from . import db as db_mod

        return jsonify({"domains": db_mod.list_domains(_db())})

    @app.post("/api/domains")
    @require_auth
    def api_domain_add():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod

        payload = request.get_json(silent=True) or {}
        domain = str(payload.get("domain", "")).strip()
        try:
            port = int(payload.get("port", 443))
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid port"}), 400
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        try:
            did = db_mod.add_domain(_db(), domain, port, source="ui")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"id": did, "domains": db_mod.list_domains(_db())})

    @app.patch("/api/domains/<int:domain_id>")
    @require_auth
    def api_domain_toggle(domain_id: int):
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod

        payload = request.get_json(silent=True) or {}
        if "enabled" not in payload:
            return jsonify({"error": "'enabled' (true/false) is required"}), 400
        ok = db_mod.set_domain_enabled(_db(), domain_id, bool(payload["enabled"]))
        if not ok:
            return jsonify({"error": "Domain not found"}), 404
        return jsonify({"ok": True, "domains": db_mod.list_domains(_db())})

    def _parse_id_list(payload: dict) -> tuple[list[int], str | None]:
        raw = payload.get("ids", payload.get("domain_ids", []))
        if not isinstance(raw, list):
            return [], "'ids' must be a list of domain ids"
        clean: list[int] = []
        for item in raw:
            try:
                iv = int(item)
            except (TypeError, ValueError):
                return [], f"Invalid domain id: {item!r}"
            if iv > 0:
                clean.append(iv)
        clean = sorted(set(clean))[:MAX_DOMAINS]
        if not clean:
            return [], "No valid domain ids provided"
        return clean, None

    @app.delete("/api/domains")
    @require_auth
    def api_domains_bulk_delete():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod

        payload = request.get_json(silent=True) or {}
        ids, err = _parse_id_list(payload)
        if err:
            return jsonify({"error": err}), 400
        deleted = db_mod.delete_domains(_db(), ids)
        return jsonify({"ok": True, "deleted": deleted, "domains": db_mod.list_domains(_db())})

    @app.patch("/api/domains")
    @require_auth
    def api_domains_bulk_toggle():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod

        payload = request.get_json(silent=True) or {}
        if "enabled" not in payload:
            return jsonify({"error": "'enabled' (true/false) and 'ids' are required"}), 400
        ids, err = _parse_id_list(payload)
        if err:
            return jsonify({"error": err}), 400
        updated = db_mod.set_domains_enabled(_db(), ids, bool(payload["enabled"]))
        return jsonify({"ok": True, "updated": updated, "domains": db_mod.list_domains(_db())})

    @app.post("/api/domains/bulk-delete")
    @require_auth
    def api_domains_bulk_delete_alias():
        # Alias for clients/proxies that block DELETE-with-body.
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod

        payload = request.get_json(silent=True) or {}
        ids, err = _parse_id_list(payload)
        if err:
            return jsonify({"error": err}), 400
        deleted = db_mod.delete_domains(_db(), ids)
        return jsonify({"ok": True, "deleted": deleted, "domains": db_mod.list_domains(_db())})

    @app.delete("/api/domains/<int:domain_id>")
    @require_auth
    def api_domain_delete(domain_id: int):
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod

        ok = db_mod.delete_domain(_db(), domain_id)
        if not ok:
            return jsonify({"error": "Domain not found"}), 404
        return jsonify({"ok": True, "domains": db_mod.list_domains(_db())})

    @app.post("/api/domains/import")
    @require_auth
    def api_domains_import():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod
        from . import parsing as parsing_mod

        ctype = request.content_type or ""
        if "multipart/form-data" in ctype:
            f = request.files.get("file")
            text = request.form.get("domains_text", "") or ""
            if f and f.filename:
                try:
                    _check_txt_filename(f.filename)
                except ValueError as exc:
                    return jsonify({"error": str(exc)}), 400
                data = f.read()
                if len(data) > MAX_UPLOAD_BYTES:
                    return jsonify({"error": "Upload exceeds 5 MB limit"}), 413
                text += "\n" + data.decode("utf-8", errors="replace")
        else:
            payload = request.get_json(silent=True) or {}
            text = str(payload.get("domains_text", "") or "")
            if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
                return jsonify({"error": "Input exceeds 5 MB limit"}), 413
        items = parsing_mod.parse_text(text)
        if not items:
            return jsonify({"error": "No valid domains found in input"}), 400
        if len(items) > MAX_DOMAINS:
            return jsonify({"error": f"Too many domains: {len(items)} > {MAX_DOMAINS}"}), 400
        before = {(d["domain"], d["port"]) for d in db_mod.list_domains(_db())}
        for host, port in items:
            db_mod.add_domain(_db(), host, port, source="import")
        after = db_mod.list_domains(_db())
        added = sum(1 for d in after if (d["domain"], d["port"]) not in before)
        return jsonify(
            {"added": added, "total": len(items), "domains": after}
        )

    @app.get("/api/history")
    @require_auth
    def api_history():
        from . import db as db_mod

        try:
            domain_id = int(request.args.get("domain_id", "0"))
            limit = min(max(int(request.args.get("limit", "100")), 1), 1000)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid domain_id/limit"}), 400
        if domain_id <= 0:
            return jsonify({"error": "domain_id is required"}), 400
        return jsonify({"history": db_mod.get_history(_db(), domain_id, limit)})

    @app.get("/api/analytics")
    @require_auth
    def api_analytics():
        from . import db as db_mod

        data = db_mod.analytics(_db())
        sched = app.config.get("SSL_SCHEDULER")
        data["scheduler"] = sched.status() if sched is not None else {"running": False}
        return jsonify(data)

    @app.get("/api/alerts")
    @require_auth
    def api_alerts():
        from . import db as db_mod

        try:
            limit = min(max(int(request.args.get("limit", "50")), 1), 500)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid limit"}), 400
        return jsonify({"alerts": db_mod.list_alerts(_db(), limit)})

    # ------------------------------- Settings page ----------------------
    @app.get("/api/settings")
    @require_auth
    def api_settings():
        from . import db as db_mod

        return jsonify(db_mod.get_settings_view(_db()))

    @app.put("/api/settings")
    @require_auth
    def api_settings_update():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        from . import db as db_mod

        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object expected"}), 400
        # Validate everything first so a bad value can't half-apply.
        valid: dict[str, str] = {}
        errors: dict[str, str] = {}
        for key, raw in payload.items():
            if key == "clear_webhook":
                continue
            if key not in db_mod.SETTING_DEFS:
                errors[key] = "Unknown setting"
                continue
            if key == "teams_webhook_url" and (raw is None or str(raw) == ""):
                continue  # untouched password field: leave as-is (use clear_webhook to remove)
            try:
                valid[key] = db_mod._validate_setting(key, str(raw))
            except ValueError as exc:
                errors[key] = str(exc)
        if errors:
            return jsonify({"error": "Validation failed", "errors": errors}), 400
        for key, clean in valid.items():
            db_mod.set_setting(_db(), key, clean)
        if payload.get("clear_webhook"):
            db_mod.clear_setting(_db(), "teams_webhook_url")
        return jsonify(db_mod.get_settings_view(_db()))

    @app.post("/api/settings/test")
    @require_auth
    def api_settings_test():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        sched = app.config.get("SSL_SCHEDULER")
        cfg = sched.effective_config() if sched is not None else {}
        url, source = sched._resolve_webhook() if sched is not None else (None, "unset")
        if url is None:
            return jsonify({"ok": False, "message": "No Teams webhook is set (Settings page or env)"}), 400
        card = teams_mod.build_test_card(cfg.get("ui_url") or None, tz_name=cfg.get("display_timezone"))
        ok, msg = teams_mod.send_payload(url, card)
        # Never echo the URL — masked source only.
        return jsonify({"ok": ok, "message": msg, "webhook_source": source}), (200 if ok else 502)

    return app


def _results_from_snapshot(snap: list[dict]):
    """Rebuild CertResult objects from a client snapshot (validated + sanitized)."""
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from .checker import CertResult

    results: list[CertResult] = []
    for item in snap[:MAX_DOMAINS]:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain", ""))[:253].lower().strip()
        try:
            port = int(item.get("port", 443))
        except (TypeError, ValueError):
            port = 443
        if not domain or not 1 <= port <= 65535:
            continue
        r = CertResult(domain=domain, port=port)
        r.success = bool(item.get("success", False))
        r.status = str(item.get("status", "ERROR"))[:16].upper()
        if r.status not in ("OK", "WARNING", "CRITICAL", "EXPIRED", "ERROR"):
            r.status = "ERROR"
        try:
            dr = item.get("days_remaining")
            r.days_remaining = int(dr) if dr is not None and str(dr).lstrip("-").isdigit() else None
        except (TypeError, ValueError):
            r.days_remaining = None
        exp = item.get("expires_on")
        if exp:
            try:
                r.expires_on = _dt.fromisoformat(str(exp))
                if r.expires_on.tzinfo is None:
                    r.expires_on = r.expires_on.replace(tzinfo=_tz.utc)
            except ValueError:
                r.expires_on = None
        r.issuer = str(item.get("issuer", ""))[:500]
        r.note = str(item.get("note", ""))[:500]
        r.error = str(item.get("error", ""))[:500]
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Single-page UI — offline assets (no external CDN).
# Shell lives here; CSS/JS/icons/fonts in assets/. TZ via <meta> tags.
# All dynamic DOM is built with textContent/createElement (XSS-safe).
# ---------------------------------------------------------------------------
_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="__CSRF_TOKEN__">
<meta name="display-tz" content="__DISPLAY_TZ__">
<meta name="tz-label" content="__TZ_LABEL__">
<meta name="description" content="SSL Checker — monitor TLS certificate expiry, analytics and Teams milestone alerts.">
<meta name="theme-color" content="#0c1930">
<link rel="icon" href="/assets/img/favicon.svg?v=__ASSETS_V__" type="image/svg+xml">
<title>SSL Checker — Certificate Expiry Monitor</title>
<link rel="stylesheet" href="/assets/css/app.css?v=__ASSETS_V__">
</head>
<body>
<div class="shell">
<aside class="sidebar" id="sidebar">
<div class="brand"><div class="logo"><i data-lucide="shield-check"></i></div>
<div><div class="brand-name">SSL Checker</div><div class="brand-sub">Expiry Monitor</div></div></div>
<nav class="nav" aria-label="Primary">
<div class="nav-cap">Monitor</div>
<button class="navlink active" data-view="dashboard" type="button"><i data-lucide="layout-dashboard"></i><span>Dashboard</span></button>
<button class="navlink" data-view="certs" type="button"><i data-lucide="shield-check"></i><span>Import Domains</span></button>
<button class="navlink" data-view="domains" type="button"><i data-lucide="server"></i><span>Domains</span><span class="navcount" id="navDomCount">0</span></button>
<div class="nav-cap">Insights</div>
<button class="navlink" data-view="analytics" type="button"><i data-lucide="chart-column"></i><span>Analytics</span></button>
<button class="navlink" data-view="settings" type="button"><i data-lucide="settings"></i><span>Settings</span></button>
</nav>
<div class="sidefoot"><div id="navSched"><span class="sched-dot"></span>Scheduler…</div><div class="sideauth">__AUTH_NOTE__</div><div>Checks use SNI + 5s timeout · SQLite store</div></div>
</aside>
<div class="main">
<header class="topbar">
<button class="menu-btn" id="navToggle" type="button" aria-label="Open navigation"><i data-lucide="menu"></i></button>
<div><h1 id="navTitle">Dashboard</h1><div class="crumb" id="navCrumb">Fleet health at a glance</div></div>
<div class="spacer"></div>
<button class="btn ghost small" id="btnTheme" type="button" title="Toggle light / dark theme"><i data-lucide="sun"></i><span id="themeLabel">Light</span></button>
<div class="pill" id="lastChecked">Not checked yet</div>
</header>
<div class="wrap">
<section class="view active" id="view-dashboard">
<section class="cards" aria-label="Summary">
<div class="card stat total" data-f="" tabindex="0" role="button" title="Show all results"><div class="n" id="sTotal">0</div><div class="l">Total</div><div class="h">all checked</div></div>
<div class="card stat ok" data-f="OK" tabindex="0" role="button" title="Filter: OK"><div class="n" id="sOk">0</div><div class="l">OK</div><div class="h">&gt; 30 days</div></div>
<div class="card stat warning" data-f="WARNING" tabindex="0" role="button" title="Filter: warning"><div class="n" id="sWarn">0</div><div class="l">Warning</div><div class="h">≤ 30 days</div></div>
<div class="card stat critical" data-f="CRITICAL" tabindex="0" role="button" title="Filter: critical"><div class="n" id="sCrit">0</div><div class="l">Critical</div><div class="h">≤ 7 days</div></div>
<div class="card stat expired" data-f="EXPIRED" tabindex="0" role="button" title="Filter: expired"><div class="n" id="sExp">0</div><div class="l">Expired</div><div class="h">needs action</div></div>
<div class="card stat failed" data-f="ERROR" tabindex="0" role="button" title="Show errors"><div class="n" id="sFail">0</div><div class="l">Failed</div><div class="h">unreachable</div></div>
</section>
<section class="panel">
<div class="panel-head"><span class="kicker">Fleet</span><h2>Status &amp; expiry overview</h2></div>
<p class="sub">Latest result per monitored domain. Select a summary card above to inspect certificates by status.</p>
<div class="grid2">
<div><h3>Status mix (latest per domain)</h3><div class="mixbar" id="mixBar"></div><div class="legend" id="mixLegend"></div></div>
<div><h3>Expiry buckets (enabled domains)</h3><div class="bars" id="buckets"></div></div>
</div>
</section>
</section>
<section class="view" id="view-certs">
<section class="panel">
<div class="panel-head"><span class="kicker">Check</span><h2>Input domains</h2></div>
<p class="sub">One per line — <span class="mono">example.com</span>, <span class="mono">example.com:8443</span>, <span class="mono">https://example.com/path</span>. Max 500 / 5&nbsp;MB. Lines starting with <span class="mono">#</span> ignored. File uploads accept <span class="mono">.txt</span> only.</p>
<label for="domains"><b>Paste domains</b></label>
<textarea id="domains" placeholder="example.com&#10;example.com:8443&#10;https://expired.badssl.com&#10;# comment ignored"></textarea>
<div class="row">
<button class="btn ghost" id="btnUploadModal" type="button"><i data-lucide="paperclip"></i><span>Upload domains.txt</span></button>
<button class="btn ghost" id="btnDefault" type="button"><i data-lucide="download"></i><span>Load default list</span></button>
<button class="btn primary" id="btnCheck" type="button"><i data-lucide="play"></i><span>Check certificates</span></button>
<span class="count-chip" id="inputCount">0 lines</span>
</div>
<div class="progress" id="progress"><div id="bar"></div></div>
<div class="skeleton" id="skeleton"><div class="sk"><div style="width:90%"></div></div><div class="sk"><div style="width:70%"></div></div><div class="sk"><div style="width:80%"></div></div></div>
<div class="errbox" id="errbox"></div>
</section>
<section class="panel">
<div class="panel-head"><span class="kicker">Results</span><h2>Certificates <span class="muted">— soonest expiry first</span></h2></div>
<p class="sub">Click a column header to sort · use search + status filter · failed domains appear under Errors.</p>
<div class="toolbar">
<input type="search" id="q" placeholder="Search domain, issuer, note…">
<select id="fStatus"><option value="">All statuses</option><option>OK</option><option>WARNING</option><option>CRITICAL</option><option>EXPIRED</option><option>ERROR</option></select>
<span class="muted">Expires</span><input type="date" id="fFrom" aria-label="Expires from" title="Expires from"><input type="date" id="fTo" aria-label="Expires to" title="Expires to">
<button class="btn ghost" id="btnClearFilters" type="button" title="Clear search, status and expiry filters"><i data-lucide="filter-x"></i><span>Clear</span></button>
<button class="btn ghost" id="dlCsv" type="button"><i data-lucide="file-down"></i><span>CSV</span></button>
<button class="btn ghost" id="dlJson" type="button"><i data-lucide="file-json"></i><span>JSON</span></button>
<button class="btn ghost" id="dlHtml" type="button"><i data-lucide="file-code"></i><span>HTML</span></button>
<button class="btn teams" id="btnTeams" type="button"><i data-lucide="send"></i><span>Send to Teams</span></button>
<button class="btn ghost" id="btnMonitorAll" type="button" title="Add every listed result (including errors) to the monitored watch list"><i data-lucide="server-plus"></i><span>Monitor all</span></button>
</div>
<div style="overflow:auto">
<table id="tbl"><thead><tr>
<th data-k="domain">Domain <i data-lucide="arrow-up-down"></i></th><th data-k="port">Port <i data-lucide="arrow-up-down"></i></th><th data-k="expires">Expires On (__TZ_LABEL__) <i data-lucide="arrow-up-down"></i></th>
<th data-k="days">Expires In <i data-lucide="arrow-up-down"></i></th><th data-k="status">Status <i data-lucide="arrow-up-down"></i></th><th>Issuer</th><th>Note</th>
</tr></thead><tbody id="tbody"><tr><td colspan="7" class="muted">No results yet — paste domains and press Check.</td></tr></tbody></table>
</div>
<div class="pager" id="certPager">
<button class="btn ghost small" id="certPrev" type="button"><i data-lucide="chevron-left"></i><span>Prev</span></button>
<span class="count-chip" id="certPageInfo" aria-live="polite">Page 1 of 1</span>
<button class="btn ghost small" id="certNext" type="button"><span>Next</span><i data-lucide="chevron-right"></i></button>
<select id="certPerPage" aria-label="Rows per page"><option value="10">10 / page</option><option value="20" selected>20 / page</option><option value="50">50 / page</option><option value="100">100 / page</option><option value="all">All rows</option></select>
</div>
<details open><summary><i data-lucide="triangle-alert"></i> Errors (<span id="errCount">0</span>)</summary>
<div style="overflow:auto;margin-top:8px">
<table><thead><tr><th>Domain</th><th>Port</th><th>Status</th><th>Error</th></tr></thead>
<tbody id="ebody"><tr><td colspan="4" class="muted">No errors.</td></tr></tbody></table>
</div></details>
</section>
</section>
<section class="view" id="view-domains">
<section class="panel">
<div class="panel-head"><span class="kicker">Monitor</span><h2>Monitored domains <span class="muted">— auto-checked every 5 min</span></h2></div>
<p class="sub">Watch list stored in SQLite. <span class="count-chip" id="schedStatus">Scheduler: …</span>
Alerts fire once at 30 days and 15 days remaining, then daily from 14 days down to expiry.</p>
<div class="toolbar">
<button class="btn primary small" id="btnCheckNow" type="button"><i data-lucide="refresh-cw"></i><span>Check now</span></button>
<button class="btn ghost small" id="btnRefreshDb" type="button"><i data-lucide="rotate-cw"></i><span>Refresh</span></button>
<button class="btn ghost small" id="dlDbCsv" type="button" title="Export watch list as CSV"><i data-lucide="file-down"></i><span>CSV</span></button>
<button class="btn ghost small" id="dlDbJson" type="button" title="Export watch list as JSON"><i data-lucide="file-json"></i><span>JSON</span></button>
<button class="btn ghost small" id="dlDbHtml" type="button" title="Export watch list as HTML report"><i data-lucide="file-code"></i><span>HTML</span></button>
<span class="muted">Expiry</span><input type="date" id="fDbFrom" aria-label="Expiry from" title="Expiry from"><input type="date" id="fDbTo" aria-label="Expiry to" title="Expiry to">
<button class="btn ghost small" id="btnClearDbFilters" type="button" title="Clear search and expiry filters"><i data-lucide="filter-x"></i><span>Clear</span></button>
<span class="count-chip" id="dbCount">0 monitored</span>
</div>
<div class="toolbar">
<input type="search" id="dbQ" placeholder="Search monitored domains…" aria-label="Search monitored domains">
</div>
<div class="formrow">
<input id="newDomain" placeholder="new-domain.com" autocomplete="off">
<input id="newPort" placeholder="443" inputmode="numeric" autocomplete="off">
<button class="btn ghost small" id="btnAdd" type="button"><i data-lucide="plus"></i><span>Add domain</span></button>
<button class="btn ghost small" id="btnImportDb" type="button"><i data-lucide="upload"></i><span>Import pasted list into watch list</span></button>
<label class="btn ghost small" for="dbFile"><i data-lucide="paperclip"></i><span>Import .txt file</span><input type="file" id="dbFile" accept=".txt" hidden></label>
<a class="btn ghost small" href="/assets/samples/import-sample.txt?v=__ASSETS_V__" download="import-sample.txt"><i data-lucide="file-down"></i><span>Sample import.txt</span></a>
</div>
<div class="bulkbar" id="bulkBar">
<strong id="selCount">0 selected</strong>
<button class="btn danger small" id="btnBulkDelete" type="button"><i data-lucide="trash-2"></i><span>Delete selected</span></button>
<button class="btn warnbtn small" id="btnBulkDisable" type="button"><i data-lucide="pause"></i><span>Pause selected</span></button>
<button class="btn ghost small" id="btnBulkEnable" type="button"><i data-lucide="play"></i><span>Resume selected</span></button>
<button class="btn ghost small" id="btnClearSel" type="button"><i data-lucide="x"></i><span>Clear</span></button>
<button class="btn ghost small" id="btnSelTxt" type="button" title="Export selected rows as .txt (import-compatible)"><i data-lucide="file-text"></i><span>TXT</span></button>
<button class="btn ghost small" id="btnSelCsv" type="button" title="Export selected rows as CSV"><i data-lucide="file-down"></i><span>CSV</span></button>
<button class="btn ghost small" id="btnSelHtml" type="button" title="Export selected rows as HTML report"><i data-lucide="file-code"></i><span>HTML</span></button>
</div>
<div style="overflow:auto">
<table><thead><tr><th><input type="checkbox" id="dbSelectAll" aria-label="Select all domains"></th><th data-db-k="domain">Domain <i data-lucide="arrow-up-down"></i></th><th data-db-k="ips">IPs <i data-lucide="arrow-up-down"></i></th><th data-db-k="port">Port <i data-lucide="arrow-up-down"></i></th><th>On</th><th data-db-k="checked">Last check (__TZ_LABEL__) <i data-lucide="arrow-up-down"></i></th><th data-db-k="days">Days left <i data-lucide="arrow-up-down"></i></th><th data-db-k="status">Status <i data-lucide="arrow-up-down"></i></th><th>Actions</th></tr></thead>
<tbody id="dbody"><tr><td colspan="9" class="muted">Loading…</td></tr></tbody></table>
</div>
<div class="pager" id="dbPager">
<button class="btn ghost small" id="dbPrev" type="button"><i data-lucide="chevron-left"></i><span>Prev</span></button>
<span class="count-chip" id="dbPageInfo" aria-live="polite">Page 1 of 1</span>
<button class="btn ghost small" id="dbNext" type="button"><span>Next</span><i data-lucide="chevron-right"></i></button>
<select id="dbPerPage" aria-label="Rows per page"><option value="10">10 / page</option><option value="20" selected>20 / page</option><option value="50">50 / page</option><option value="100">100 / page</option><option value="all">All rows</option></select>
</div>
<div class="histbox" id="histBox"></div>
</section>
</section>
<section class="view" id="view-analytics">
<section class="panel">
<div class="panel-head"><span class="kicker">Trends</span><h2>Activity &amp; alert history</h2></div>
<p class="sub">From recorded 5-minute checks in SQLite. Auto-refreshes every minute.</p>
<div class="grid2">
<div><h3>Status distribution — latest per enabled domain</h3><canvas class="chart donut" id="statusDonut"></canvas><div class="legend" id="statusLegend"></div></div>
<div><h3>Alerts by milestone</h3><div class="bars" id="msBars"></div><p class="sub">30d and 15d fire once per certificate; daily milestones fire once per day down to expiry.</p></div>
</div>
<h3>Checks per day — last 14 days</h3>
<canvas class="chart" id="dailyChart"></canvas>
<h3>Recent Teams alerts</h3>
<div style="overflow:auto">
<table><thead><tr><th>Domain</th><th>Milestone</th><th>Days left</th><th>Status</th><th>Sent (__TZ_LABEL__)</th></tr></thead>
<tbody id="abody"><tr><td colspan="5" class="muted">No alerts yet.</td></tr></tbody></table>
</div>
</section>
</section>
<section class="view" id="view-settings">
<section class="panel settings">
<div class="panel-head"><span class="kicker">Configure</span><h2>Settings</h2></div>
<p class="sub">Everything the checker and Teams alerts use. Priority: this page (stored in SQLite) &gt; environment variable &gt; built-in default. Secrets are never shown back — only masked.</p>
<div class="toolbar"><span class="count-chip" id="setStatus">Loading settings…</span></div>
<div class="setrow"><label for="setWebhook">Teams webhook URL<span class="src" id="src_teams_webhook_url">…</span><span class="help">Power Automate / Workflows URL. Leave blank to keep the saved value; overrides TEAMS_WEBHOOK_URL.</span></label>
<div><input type="password" id="setWebhook" placeholder="(unchanged)" autocomplete="off"><div style="margin-top:6px"><button class="btn ghost small" id="btnClearWebhook" type="button">Remove saved URL (fall back to env)</button></div></div></div>
<div class="setrow"><label for="setFormat">Teams card format<span class="src" id="src_teams_format">…</span></label>
<div><select id="setFormat"><option value="adaptive">adaptive (modern)</option><option value="messagecard">messagecard (legacy)</option></select></div></div>
<div class="setrow"><label for="setNotif">Expiry notifications<span class="src" id="src_notifications_enabled">…</span><span class="help">Off = keep checking every cycle but never send Teams alerts.</span></label>
<div><select id="setNotif"><option value="1">On — send milestone alerts</option><option value="0">Off — checks only</option></select></div></div>
<div class="setrow"><label for="setInterval">Check interval (minutes)<span class="src" id="src_check_interval_seconds">…</span><span class="help">How often every monitored domain is re-checked. 1–1440 min; takes effect on the next cycle.</span></label>
<div><input type="number" id="setInterval" min="1" max="1440" step="1"></div></div>
<div class="setrow"><label for="setTimeout">TLS timeout (seconds)<span class="src" id="src_check_timeout_seconds">…</span></label>
<div><input type="number" id="setTimeout" min="1" max="60" step="0.5"></div></div>
<div class="setrow"><label for="setWorkers">Checker workers<span class="src" id="src_check_workers">…</span><span class="help">Concurrent TLS connections per cycle. 1–100.</span></label>
<div><input type="number" id="setWorkers" min="1" max="100" step="1"></div></div>
<div class="setrow"><label for="setUiUrl">Public UI URL<span class="src" id="src_ui_url">…</span><span class="help">Link added to Teams cards, e.g. https://ssl.example.com. Blank = no link.</span></label>
<div><input type="text" id="setUiUrl" placeholder="https://…" autocomplete="off"></div></div>
<div class="setrow"><label for="setPriv">Allow private targets<span class="src" id="src_allow_private">…</span><span class="help">Off = block private/loopback/link-local targets (SSRF protection).</span></label>
<div><select id="setPriv"><option value="0">Off — block private targets</option><option value="1">On — allow internal domains</option></select></div></div>
<div class="setrow"><label for="setTz">Display timezone<span class="src" id="src_display_timezone">…</span><span class="help">IANA zone for all displayed times, e.g. Asia/Kathmandu or UTC. Storage stays UTC.</span></label>
<div><input type="text" id="setTz" placeholder="Asia/Kathmandu" autocomplete="off"></div></div>
<div class="row">
<button class="btn primary" id="btnSaveSettings" type="button"><i data-lucide="save"></i><span>Save settings</span></button>
<button class="btn teams" id="btnTestWebhook" type="button"><i data-lucide="mail"></i><span>Send test card</span></button>
<span class="muted" id="setMsg"></span>
</div>
</section>
</section>
<div class="footer">SSL Checker · CLI + Web + Teams · SQLite store · <span id="footTime"></span> · Powered by <a href="https://sagarmalla.info.np">Sagar Malla</a></div>
</div>
</div>
</div>
<button class="gotop" id="goTop" type="button" aria-label="Back to top"><i data-lucide="arrow-up"></i></button>
<div class="toast" id="toast"></div>
<div class="modal-backdrop" id="uploadModal" aria-hidden="true">
<div class="modal" role="dialog" aria-modal="true" aria-labelledby="uploadModalTitle">
<div class="modal-head"><h2 id="uploadModalTitle"><i data-lucide="upload"></i> Upload domains.txt</h2><button class="icon-btn" id="uploadModalClose" type="button" aria-label="Close upload dialog"><i data-lucide="x"></i></button></div>
<p class="sub">Plain <span class="mono">.txt</span> only, one domain per line. Max 500 / 5&nbsp;MB. Dropped files are appended to the textarea and checked immediately.</p>
<div class="dropzone" id="dropzone" tabindex="0" aria-label="Drop a .txt file here or browse">
<i data-lucide="folder-open"></i>
<p><b>Drag &amp; drop your .txt file here</b></p>
<p class="muted">or</p>
<button class="btn ghost" id="btnBrowse" type="button"><i data-lucide="folder-open"></i><span>Browse files</span></button>
<input type="file" id="file" accept=".txt" hidden>
</div>
<div class="errbox" id="uploadErr"></div>
<div class="modal-foot">
<a class="btn ghost small" href="/assets/samples/import-sample.txt?v=__ASSETS_V__" download="import-sample.txt"><i data-lucide="file-down"></i><span>Download Sample.txt</span></a>
<span class="spacer"></span>
<button class="btn ghost small" id="uploadModalCancel" type="button">Cancel</button>
</div>
</div>
</div>
<script src="/assets/js/lucide.min.js?v=__ASSETS_V__" defer></script>
<script src="/assets/js/app.js?v=__ASSETS_V__" defer></script>
</body>
</html>"""
