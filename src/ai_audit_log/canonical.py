"""AIAuditLog canonical JSON profile.

This profile normalizes AIAuditLog-specific Python values and then delegates
JSON byte serialization to the maintained ``rfc8785`` package.
"""

from __future__ import annotations

import math
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import rfc8785

from ai_audit_log.exceptions import CanonicalizationError
from ai_audit_log.time import format_rfc3339


def normalize_for_json(value: Any) -> Any:
    """Convert supported Python values to deterministic JSON-compatible values."""

    if value is None or isinstance(value, bool | str | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("NaN and Infinity are unsupported")
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalizationError("non-finite Decimal values are unsupported")
        return format(value.normalize(), "f")
    if isinstance(value, datetime):
        return format_rfc3339(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list | tuple):
        return [normalize_for_json(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            normalized[key] = normalize_for_json(item)
        return normalized
    if hasattr(value, "model_dump"):
        return normalize_for_json(value.model_dump(mode="python", exclude_none=True))
    raise CanonicalizationError(f"unsupported canonical value type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return RFC 8785 canonical UTF-8 JSON bytes for supported values."""

    normalized = normalize_for_json(value)
    try:
        return rfc8785.dumps(normalized)
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalizationError(str(exc)) from exc
