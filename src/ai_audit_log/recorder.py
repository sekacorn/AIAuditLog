"""High-level audit recorder."""

from __future__ import annotations

from ai_audit_log.builder import EventBuilder
from ai_audit_log.chain import append_integrity
from ai_audit_log.models import AuditEvent, Outcome
from ai_audit_log.rotation import RotationPolicy, rotate_stream, rotation_decision
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

        existing = self.store.read_all()
        previous = existing[-1].integrity.event_digest if existing else None
        chained = append_integrity(
            event,
            stream_id=self.stream_id,
            sequence=len(existing) + 1,
            previous_event_digest=previous,
        )
        if self.rotation_policy is not None:
            decision = rotation_decision(self.store.path, self.rotation_policy, next_event=chained)
            if decision.should_rotate and self.store.path.exists():
                rotate_stream(self.store.path, self.rotation_policy)
        self.store.append(chained)
        if self.index is not None:
            self.index.append(chained)
        return chained

    def record(self, *, event_type: str, outcome: Outcome, data: dict[str, object] | None = None) -> AuditEvent:
        """Create and append one event."""

        return self.append_event(self.builder.create(event_type=event_type, outcome=outcome, data=data or {}))
