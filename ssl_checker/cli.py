"""Command-line interface: ``check`` (default) | ``serve`` | ``notify``."""
from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone

from . import checker as checker_mod
from . import evaluate as eval_mod
from . import notify_teams as teams_mod
from . import parsing as parsing_mod
from . import render as render_mod

log = logging.getLogger("ssl_checker")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ssl-checker",
        description="Check SSL/TLS certificate expiry for a list of domains.",
    )
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    sub = p.add_subparsers(dest="command")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--file", default="domains.txt", help="Domains file (default: domains.txt)")
        sp.add_argument("--domain", action="append", default=[], help="Extra domain (repeatable)")
        sp.add_argument("--workers", type=int, default=20, help="Concurrent workers (default: 20)")
        sp.add_argument("--timeout", type=float, default=5.0, help="TLS timeout seconds (default: 5)")
        sp.add_argument("--critical", type=int, default=7, help="Critical threshold days (default: 7)")
        sp.add_argument("--warning", type=int, default=30, help="Warning threshold days (default: 30)")
        sp.add_argument("--format", choices=["table", "csv", "json", "html"], default="table")
        sp.add_argument("--output", default=None, help="Write output to FILE instead of stdout")
        sp.add_argument("--tz", default=None, help="Display timezone, e.g. Asia/Kathmandu (default: $SSL_DISPLAY_TZ or Asia/Kathmandu)")
        sp.add_argument("--allow-private", action="store_true", help="Allow private/loopback targets (SSRF guard off)")

    check_p = sub.add_parser("check", help="Check certificates and print a report")
    add_common(check_p)

    serve_p = sub.add_parser("serve", help="Run the web UI")
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    serve_p.add_argument("--allow-private", action="store_true")
    serve_p.add_argument("--file", default="domains.txt", help="Seed file for the DB watch list")
    serve_p.add_argument("--db", default=None, help="SQLite path (default: $SSL_DB_PATH or data/ssl_checker.db)")
    serve_p.add_argument("--interval", type=int, default=300, help="Scheduled re-check seconds (default: 300)")
    serve_p.add_argument("--no-scheduler", action="store_true", help="Disable the background 5-min checker")

    sched_p = sub.add_parser("scheduler", help="Run the 5-minute check loop (no web UI)")
    sched_p.add_argument("--db", default=None, help="SQLite path (default: $SSL_DB_PATH or data/ssl_checker.db)")
    sched_p.add_argument("--interval", type=int, default=300, help="Re-check seconds (default: 300)")
    sched_p.add_argument("--allow-private", action="store_true")
    sched_p.add_argument("--workers", type=int, default=20)
    sched_p.add_argument("--timeout", type=float, default=5.0)
    sched_p.add_argument("--teams-webhook-env", default="TEAMS_WEBHOOK_URL")
    sched_p.add_argument("--teams-format", choices=["adaptive", "messagecard"], default="adaptive")
    sched_p.add_argument("--ui-url", default=None)
    sched_p.add_argument("--once", action="store_true", help="Run a single cycle and exit")

    da_p = sub.add_parser("domain-add", help="Add a domain to the SQLite watch list")
    da_p.add_argument("--domain", required=True, help="Hostname (e.g. example.com)")
    da_p.add_argument("--port", type=int, default=443)
    da_p.add_argument("--db", default=None)

    dl_p = sub.add_parser("domain-list", help="List monitored domains + latest status")
    dl_p.add_argument("--db", default=None)

    dr_p = sub.add_parser("domain-remove", help="Remove a domain from monitoring")
    dr_p.add_argument("--id", type=int, required=True, help="Domain id from domain-list")
    dr_p.add_argument("--db", default=None)

    seed_p = sub.add_parser("db-seed", help="Import a domains.txt file into SQLite")
    seed_p.add_argument("--file", default="domains.txt")
    seed_p.add_argument("--db", default=None)

    notify_p = sub.add_parser("notify", help="Check certificates and send to Teams")
    add_common(notify_p)
    notify_p.add_argument("--teams-webhook-env", default="TEAMS_WEBHOOK_URL")
    notify_p.add_argument("--teams-format", choices=["adaptive", "messagecard"], default="adaptive")
    notify_p.add_argument("--notify-on", choices=["warning", "critical", "always"], default="warning")
    notify_p.add_argument("--ui-url", default=None, help="Link to the web UI inside the Teams card")
    notify_p.add_argument("--dry-run", action="store_true", help="Print Teams JSON instead of sending")
    notify_p.add_argument("--state-file", default=None, help="JSON file tracking last notified state")
    notify_p.add_argument("--remind-every", default="24h", help="Reminder cadence (e.g. 24h, 30m, 1d)")
    return p


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def collect_domains(args: argparse.Namespace) -> list[tuple[str, int]]:
    """Merge --domain flags with --file contents (CLI path)."""
    domains: list[tuple[str, int]] = []
    for d in getattr(args, "domain", []) or []:
        item = parsing_mod.parse_domain_line(d)
        if item is None:
            log.warning("Ignoring invalid --domain value: %r", d)
        else:
            domains.append(item)
    file_path = getattr(args, "file", None)
    if file_path and os.path.exists(file_path):
        try:
            domains.extend(parsing_mod.parse_file(file_path))
        except Exception as exc:
            log.error("Could not read domains file %s: %s", file_path, exc)
            raise SystemExit(3)
    elif file_path and getattr(args, "domain", None):
        # --domain given but file missing: not fatal.
        log.debug("Domains file %s not found; using --domain only", file_path)
    elif file_path:
        log.error("Domains file not found: %s (use --file or --domain)", file_path)
        raise SystemExit(3)
    domains = parsing_mod.dedupe(domains)
    if not domains:
        log.error("No valid domains found")
        raise SystemExit(3)
    return domains


def run_check(args: argparse.Namespace) -> int:
    try:
        domains = collect_domains(args)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 3
    log.info("Checking %d domain(s) with %d workers", len(domains), args.workers)
    results = checker_mod.check_domains(domains, workers=args.workers, timeout=args.timeout)
    eval_mod.apply_status(results, critical=args.critical, warning=args.warning)
    summary = eval_mod.summarize(results)
    use_color = render_mod.detect_color(args.no_color) and args.output is None
    fmt = args.format
    tz_name = getattr(args, "tz", None)
    if fmt == "table":
        content = render_mod.render_table(results, use_color=use_color, tz_name=tz_name) + "\n" + render_mod.summary_line(summary) + "\n"
    elif fmt == "csv":
        content = render_mod.render_csv(results)
    elif fmt == "json":
        content = render_mod.render_json(results, summary)
    else:
        content = render_mod.render_html(results, summary, tz_name=tz_name)
    render_mod.write_output(content, args.output)
    if args.output is None and fmt == "table":
        pass  # summary already included
    elif args.output is not None or fmt != "table":
        # Always echo the one-line summary to stderr for cron/Jenkins visibility,
        # except when table already printed it to the same stream.
        if args.output is not None:
            print(render_mod.summary_line(summary), file=sys.stderr)
    return eval_mod.exit_code(summary)


def run_serve(args: argparse.Namespace) -> int:
    from .web import create_app

    app = create_app(
        default_file=getattr(args, "file", "domains.txt"),
        allow_private=getattr(args, "allow_private", False),
        db_path=getattr(args, "db", None),
        enable_scheduler=not getattr(args, "no_scheduler", False),
        check_interval=getattr(args, "interval", 300),
    )
    log.info("Serving on http://%s:%d", args.host, args.port)
    # Never debug in production.
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def run_scheduler_cmd(args: argparse.Namespace) -> int:
    import os as _os

    from . import db as db_mod
    from . import scheduler as sched_mod

    db_path = db_mod.init_db(db_mod.resolve_db_path(getattr(args, "db", None)))
    sched = sched_mod.Scheduler(
        db_path,
        interval_seconds=getattr(args, "interval", 300),
        allow_private=getattr(args, "allow_private", False),
        workers=getattr(args, "workers", 20),
        timeout=getattr(args, "timeout", 5.0),
        teams_env=getattr(args, "teams_webhook_env", "TEAMS_WEBHOOK_URL"),
        teams_format=getattr(args, "teams_format", "adaptive"),
        ui_url=getattr(args, "ui_url", None) or _os.environ.get("SSL_UI_URL"),
    )
    if getattr(args, "once", False):
        summary = sched.run_cycle()
        print(f"Checked {summary.get('checked', 0)} domain(s); alerts due: "
              f"{summary.get('alerts_due', 0)}; {summary.get('detail', '')}")
        return 0
    return sched_mod.run_forever(
        db_path,
        interval_seconds=sched.interval_seconds,
        allow_private=sched.allow_private,
        workers=sched.workers,
        timeout=sched.timeout,
        teams_env=sched.teams_env,
        teams_format=sched.teams_format,
        ui_url=sched.ui_url,
    )


def run_domain_add(args: argparse.Namespace) -> int:
    from . import db as db_mod

    db_path = db_mod.init_db(db_mod.resolve_db_path(getattr(args, "db", None)))
    try:
        did = db_mod.add_domain(db_path, args.domain, args.port)
    except ValueError as exc:
        log.error("%s", exc)
        return 3
    print(f"Monitoring #{did}: {args.domain}:{args.port} (db={db_path})")
    return 0


def run_domain_list(args: argparse.Namespace) -> int:
    from . import db as db_mod

    db_path = db_mod.init_db(db_mod.resolve_db_path(getattr(args, "db", None)))
    rows = db_mod.list_domains(db_path)
    if not rows:
        print("Watch list is empty. Add with: domain-add --domain example.com")
        return 0
    print(f"{'ID':>4}  {'Domain':<40} {'Port':>5}  {'On':>3}  {'Days':>5}  Status")
    for r in rows:
        days = r["last_days"] if r["last_days"] is not None else "-"
        print(f"{r['id']:>4}  {r['domain']:<40} {r['port']:>5}  "
              f"{'y' if r['enabled'] else 'n':>3}  {str(days):>5}  {r['last_status'] or 'NEW'}")
    return 0


def run_domain_remove(args: argparse.Namespace) -> int:
    from . import db as db_mod

    db_path = db_mod.init_db(db_mod.resolve_db_path(getattr(args, "db", None)))
    if db_mod.delete_domain(db_path, args.id):
        print(f"Removed domain #{args.id}")
        return 0
    log.error("Domain id %d not found", args.id)
    return 3


def run_db_seed(args: argparse.Namespace) -> int:
    from . import db as db_mod

    db_path = db_mod.init_db(db_mod.resolve_db_path(getattr(args, "db", None)))
    added = db_mod.seed_from_file(db_path, args.file)
    print(f"Seeded {added} new domain(s) from {args.file} into {db_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # `check` is the default command when none is given.
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    _known = ("check", "serve", "notify", "scheduler", "domain-add",
              "domain-list", "domain-remove", "db-seed", "-h", "--help")
    if not raw or (raw and raw[0] not in _known):
        raw = ["check", *raw]
    try:
        args = parser.parse_args(raw)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 3
    setup_logging(getattr(args, "verbose", False))
    try:
        if args.command == "serve":
            return run_serve(args)
        if args.command == "scheduler":
            return run_scheduler_cmd(args)
        if args.command == "domain-add":
            return run_domain_add(args)
        if args.command == "domain-list":
            return run_domain_list(args)
        if args.command == "domain-remove":
            return run_domain_remove(args)
        if args.command == "db-seed":
            return run_db_seed(args)
        if args.command == "notify":
            # Single-pass: check+print+notify without double fetch.
            return notify_single_pass(args)
        return run_check(args)
    except KeyboardInterrupt:
        log.error("Interrupted")
        return 3
    except Exception as exc:
        log.exception("Fatal error: %s", exc)
        return 3


def notify_single_pass(args: argparse.Namespace) -> int:
    """Check once, print the report, then notify Teams (no duplicate TLS work)."""
    try:
        domains = collect_domains(args)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 3
    results = checker_mod.check_domains(domains, workers=args.workers, timeout=args.timeout)
    eval_mod.apply_status(results, critical=args.critical, warning=args.warning)
    summary = eval_mod.summarize(results)
    use_color = render_mod.detect_color(args.no_color) and args.output is None
    fmt = args.format
    tz_name = getattr(args, "tz", None)
    if fmt == "table":
        content = render_mod.render_table(results, use_color=use_color, tz_name=tz_name) + "\n" + render_mod.summary_line(summary) + "\n"
    elif fmt == "csv":
        content = render_mod.render_csv(results)
    elif fmt == "json":
        content = render_mod.render_json(results, summary)
    else:
        content = render_mod.render_html(results, summary, tz_name=tz_name)
    render_mod.write_output(content, args.output)
    if args.output is not None:
        print(render_mod.summary_line(summary), file=sys.stderr)
    code = eval_mod.exit_code(summary)
    ok, msg = teams_mod.notify(
        results,
        summary,
        webhook_env=args.teams_webhook_env,
        fmt=args.teams_format,
        notify_on=args.notify_on,
        ui_url=args.ui_url,
        dry_run=args.dry_run,
        state_file=args.state_file,
        remind_every=args.remind_every,
        tz_name=tz_name,
    )
    if args.dry_run and ok and "Skipped" not in msg:
        print(msg)
    elif ok:
        log.info("Teams: %s", msg)
    else:
        log.error("Teams notification failed: %s", msg)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
