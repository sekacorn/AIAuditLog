"""High-level audit recorder."""

from __future__ import annotations

from ai_audit_log.builder import EventBuilder
from ai_audit_log.models import AuditEvent, Outcome
from ai_audit_log.rotation import RotationPolicy
from ai_audit_log.storage import JsonlStore, SQLiteIndex


class AuditRecorder:
    """Create, chain, store, and optionally index events."""

    def __init__(
        self,
        *,
        builder: EventBuilder,
        store: JsonlStore,
        stream_id: str = "default",
        index: SQLiteIndex | None = None,
        rotation_policy: RotationPolicy | None = None,
    ) -> None:
        self.builder = builder
        self.store = store
        self.stream_id = stream_id
        self.index = index
        self.rotation_policy = rotation_policy

    def append_event(self, event: AuditEvent) -> AuditEvent:
        """Append an existing event with the next chain values."""

        chained = self.store.append_chained(
            event,
            stream_id=self.stream_id,
            rotation_policy=self.rotation_policy,
        )
        if self.index is not None:
            self.index.append(chained)
        return chained

    def record(self, *, event_type: str, outcome: Outcome, data: dict[str, object] | None = None) -> AuditEvent:
        """Create and append one event."""

        return self.append_event(self.builder.create(event_type=event_type, outcome=outcome, data=data or {}))
