"""Allow `python3 -m ssl_checker.cli` and `python3 -m ssl_checker`."""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
