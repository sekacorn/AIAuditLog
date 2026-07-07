"""Safe in-memory filtering."""

from __future__ import annotations

from collections.abc import Iterable

from ai_audit_log.models import AuditEvent


def filter_events(
    events: Iterable[AuditEvent],
    *,
    event_type: str | None = None,
    status: str | None = None,
    stream_id: str | None = None,
    limit: int = 100,
) -> list[AuditEvent]:
    """Filter events with deterministic ordering and a hard limit."""

    if limit < 1 or limit > 10_000:
        raise ValueError("limit must be between 1 and 10000")
    result: list[AuditEvent] = []
    for event in sorted(events, key=lambda item: (item.recorded_time, item.event_id)):
        if event_type is not None and event.event_type != event_type:
            continue
        if status is not None and event.outcome.status != status:
            continue
        if stream_id is not None and event.integrity.stream_id != stream_id:
            continue
        result.append(event)
        if len(result) >= limit:
            break
    return result
