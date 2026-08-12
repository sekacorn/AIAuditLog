"""Resource bounds for untrusted event and profile structures."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

MAX_EVENT_BYTES = 2_000_000
MAX_EVENT_DEPTH = 64
MAX_EVENT_ITEMS = 10_000
MAX_EVENT_STRING_CHARS = 1_000_000

MAX_PROFILE_BYTES = 256_000
MAX_PROFILE_DEPTH = 16
MAX_PROFILE_ITEMS = 1_000
MAX_PROFILE_STRING_CHARS = 8_192


def validate_bounded_structure(
    value: Any,
    *,
    label: str,
    max_depth: int,
    max_items: int,
    max_string_chars: int,
) -> None:
    """Reject overly deep, broad, or long JSON-like values."""

    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > max_depth:
            raise ValueError(f"{label} exceeds maximum nesting depth")
        if isinstance(current, str):
            if len(current) > max_string_chars:
                raise ValueError(f"{label} contains an overlong string")
            continue
        if isinstance(current, Mapping):
            if len(current) > max_items:
                raise ValueError(f"{label} contains too many mapping items")
            for key, item in current.items():
                if not isinstance(key, str):
                    raise ValueError(f"{label} mapping keys must be strings")
                if len(key) > max_string_chars:
                    raise ValueError(f"{label} contains an overlong mapping key")
                pending.append((item, depth + 1))
            continue
        if isinstance(current, Sequence) and not isinstance(current, (bytes, bytearray)):
            if len(current) > max_items:
                raise ValueError(f"{label} contains too many sequence items")
            pending.extend((item, depth + 1) for item in current)
