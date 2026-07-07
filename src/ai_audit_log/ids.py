"""Event identifier helpers."""

from __future__ import annotations

from uuid import UUID, uuid4


def new_event_id() -> str:
    """Return a sortable-preferred unique event ID.

    Python 3.11 does not provide UUIDv7 in the standard library. For alpha
    portability this package uses UUIDv4 as a safe fallback and documents that
    event IDs are unique but not time-sortable.
    """

    return str(uuid4())


def validate_event_id(value: str) -> str:
    """Validate that an event identifier is a UUID string."""

    return str(UUID(value))
