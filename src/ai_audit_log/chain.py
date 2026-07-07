"""Hash-chain append and verification."""

from __future__ import annotations

from dataclasses import dataclass, field

from ai_audit_log.constants import CHAIN_ALGORITHM, DIGEST_ALGORITHM
from ai_audit_log.digest import event_digest
from ai_audit_log.models import AuditEvent, Integrity


@dataclass(frozen=True)
class ChainIssue:
    """One chain verification issue."""

    index: int
    code: str
    message: str


@dataclass(frozen=True)
class ChainReport:
    """Result of chain verification."""

    ok: bool
    event_count: int
    stream_id: str | None
    terminal_digest: str | None
    issues: list[ChainIssue] = field(default_factory=list)


def append_integrity(
    event: AuditEvent,
    *,
    stream_id: str,
    sequence: int,
    previous_event_digest: str | None,
) -> AuditEvent:
    """Return an event with chain metadata and current digest populated."""

    event.integrity = Integrity(
        stream_id=stream_id,
        sequence=sequence,
        previous_event_digest=previous_event_digest,
        digest_algorithm=DIGEST_ALGORITHM,
        chain_algorithm=CHAIN_ALGORITHM,
    )
    event.integrity.event_digest = event_digest(event)
    return event


class ChainVerifier:
    """Verify one hash-chained stream."""

    def verify(self, events: list[AuditEvent], *, stream_id: str | None = None) -> ChainReport:
        """Verify digests, sequence numbers, and previous-digest links."""

        issues: list[ChainIssue] = []
        expected_previous: str | None = None
        expected_sequence = 1
        seen_sequences: set[int] = set()
        active_stream = stream_id
        terminal: str | None = None

        for index, event in enumerate(events):
            integrity = event.integrity
            if integrity.stream_id is None:
                issues.append(ChainIssue(index, "missing_stream", "event has no stream_id"))
            elif active_stream is None:
                active_stream = integrity.stream_id
            elif integrity.stream_id != active_stream:
                issues.append(ChainIssue(index, "stream_mixing", "event stream_id differs"))

            if integrity.sequence is None:
                issues.append(ChainIssue(index, "missing_sequence", "event has no sequence"))
            else:
                if integrity.sequence in seen_sequences:
                    issues.append(ChainIssue(index, "duplicate_sequence", "duplicate sequence"))
                seen_sequences.add(integrity.sequence)
                if integrity.sequence != expected_sequence:
                    issues.append(ChainIssue(index, "sequence_gap", "sequence is not contiguous"))
                expected_sequence += 1

            if integrity.previous_event_digest != expected_previous:
                issues.append(ChainIssue(index, "previous_digest", "previous digest mismatch"))

            calculated = event_digest(event)
            if integrity.event_digest != calculated:
                issues.append(ChainIssue(index, "event_digest", "event digest mismatch"))
            terminal = integrity.event_digest
            expected_previous = integrity.event_digest

        return ChainReport(
            ok=not issues,
            event_count=len(events),
            stream_id=active_stream,
            terminal_digest=terminal,
            issues=issues,
        )
