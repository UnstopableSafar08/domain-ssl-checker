"""WSGI / CLI entry point."""
from __future__ import annotations

import os

from ssl_checker.cli import main
from ssl_checker.web import create_app


def _check_interval() -> int:
    try:
        return max(30, int(os.environ.get("SSL_CHECK_INTERVAL_SECONDS", "300")))
    except (TypeError, ValueError):
        return 300


# Flask CLI / gunicorn support: `gunicorn app:app`
# NOTE: the in-process scheduler stays OFF here by default so multi-worker
# gunicorn never double-checks / double-alerts. Run the scheduler as a
# sidecar instead (`... scheduler` service in docker-compose.yml), or set
# SSL_ENABLE_SCHEDULER=1 with --workers 1.
app = create_app(
    default_file=os.environ.get("SSL_DOMAINS_FILE", "domains.txt"),
    allow_private=os.environ.get("SSL_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes"),
    db_path=os.environ.get("SSL_DB_PATH") or None,
    enable_scheduler=os.environ.get("SSL_ENABLE_SCHEDULER", "0").lower() in ("1", "true", "yes"),
    check_interval=_check_interval(),
)

if __name__ == "__main__":
    raise SystemExit(main())
