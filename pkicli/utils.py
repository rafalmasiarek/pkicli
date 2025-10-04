# utils.py
# Common helpers used across the CLI.
# All timestamps are UTC and formatted as RFC3339 (or compact when used in S3 keys).

from datetime import datetime, timezone
from dateutil import parser as dtp

def parse_rfc3339(s: str):
    """Parse RFC3339/ISO8601 into aware UTC datetime."""
    return dtp.isoparse(s).astimezone(timezone.utc)

def days_until(expire_str: str) -> int:
    """Return integer number of full days from now until expire_str (RFC3339).
    Returns 0 on parse errors."""
    try:
        exp = parse_rfc3339(expire_str)
        now = datetime.now(timezone.utc)
        return int((exp - now).total_seconds() // 86400)
    except Exception:
        return 0

def safe_get(d, path, default=None):
    """Safely read nested dict by dotted path, e.g. safe_get(doc,'a.b.c')."""
    cur = d
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def now_utc_str() -> str:
    """Return current UTC time as RFC3339 string, e.g. 2025-10-04T12:34:56Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def ts_compact_utc() -> str:
    """Return compact UTC timestamp for filenames/S3 keys, e.g. 20251004T123456Z."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")