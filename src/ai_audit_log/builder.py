"""Safe event builder."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ai_audit_log.ids import new_event_id
from ai_audit_log.models import Actor, AuditEvent, Outcome, Source, payload_for_event
from ai_audit_log.privacy import PrivacyProfile, redact_value
from ai_audit_log.time import now_utc


class EventBuilder:
    """Create validated, privacy-filtered audit events."""

    def __init__(self, *, source: Source, actor: Actor, privacy: PrivacyProfile | None = None) -> None:
        self.source = source
        self.actor = actor
        self.privacy = privacy or PrivacyProfile()

    def create(
        self,
        *,
        event_type: str,
        outcome: Outcome,
        data: dict[str, Any] | None = None,
        event_time: datetime | None = None,
        recorded_time: datetime | None = None,
        event_id: str | None = None,
        **extra: Any,
    ) -> AuditEvent:
        """Create one event."""

        raw_data = data or {}
        payload_for_event(event_type, raw_data)
        filtered_data = redact_value(raw_data, self.privacy)
        return AuditEvent(
            event_id=event_id or new_event_id(),
            event_type=event_type,
            event_time=event_time or now_utc(),
            recorded_time=recorded_time or now_utc(),
            source=self.source,
            actor=self.actor,
            outcome=outcome,
            data=filtered_data,
            **extra,
        )
