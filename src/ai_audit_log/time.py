"""UTC timestamp helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from ai_audit_log.exceptions import ValidationError


def now_utc() -> datetime:
    """Return the current timezone-aware UTC datetime."""

    return datetime.now(UTC)


def require_aware_utc(value: datetime) -> datetime:
    """Normalize a timezone-aware datetime to UTC or reject naive input."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


def format_rfc3339(value: datetime) -> str:
    """Format a datetime as an RFC 3339-compatible UTC string with Z suffix."""

    utc_value = require_aware_utc(value)
    text = utc_value.isoformat(timespec="microseconds")
    return text.replace("+00:00", "Z")


def parse_rfc3339(value: str) -> datetime:
    """Parse an RFC 3339-compatible timestamp and normalize to UTC."""

    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    parsed = datetime.fromisoformat(value)
    return require_aware_utc(parsed)
