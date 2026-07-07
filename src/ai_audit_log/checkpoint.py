"""Checkpoint creation and verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from ai_audit_log.chain import ChainVerifier
from ai_audit_log.constants import CHAIN_ALGORITHM
from ai_audit_log.digest import sha256_digest
from ai_audit_log.exceptions import IntegrityError
from ai_audit_log.models import AuditEvent
from ai_audit_log.time import format_rfc3339, now_utc


class Checkpoint(BaseModel):
    """Signed or unsigned stream checkpoint."""

    schema_version: str = "1.0"
    stream_id: str
    event_count: int
    terminal_digest: str | None
    chain_algorithm: str = CHAIN_ALGORITHM
    created_time: str = Field(default_factory=lambda: format_rfc3339(now_utc()))
    checkpoint_digest: str | None = None
    signatures: list[dict[str, Any]] = Field(default_factory=list)

    def unsigned_payload(self) -> dict[str, Any]:
        """Return checkpoint data covered by its digest."""

        payload = self.model_dump(exclude_none=True)
        payload.pop("checkpoint_digest", None)
        payload.pop("signatures", None)
        return payload


@dataclass(frozen=True)
class CheckpointResult:
    """Checkpoint verification result."""

    ok: bool
    issues: list[str]


def create_checkpoint(events: list[AuditEvent], *, stream_id: str | None = None) -> Checkpoint:
    """Create a checkpoint for a verified stream."""

    report = ChainVerifier().verify(events, stream_id=stream_id)
    if not report.ok:
        issue_codes = ", ".join(issue.code for issue in report.issues)
        raise IntegrityError(f"cannot checkpoint an invalid chain: {issue_codes}")
    active_stream = report.stream_id or stream_id or "default"
    checkpoint = Checkpoint(
        stream_id=active_stream,
        event_count=report.event_count,
        terminal_digest=report.terminal_digest,
    )
    checkpoint.checkpoint_digest = sha256_digest(checkpoint.unsigned_payload())
    return checkpoint


def verify_checkpoint(checkpoint: Checkpoint, events: list[AuditEvent]) -> CheckpointResult:
    """Verify a checkpoint against a stream."""

    issues: list[str] = []
    calculated = sha256_digest(checkpoint.unsigned_payload())
    if checkpoint.checkpoint_digest != calculated:
        issues.append("checkpoint digest mismatch")
    report = ChainVerifier().verify(events, stream_id=checkpoint.stream_id)
    if not report.ok:
        issues.extend(issue.code for issue in report.issues)
    if checkpoint.event_count != report.event_count:
        issues.append("event count mismatch")
    if checkpoint.terminal_digest != report.terminal_digest:
        issues.append("terminal digest mismatch")
    if checkpoint.stream_id != report.stream_id:
        issues.append("stream mismatch")
    return CheckpointResult(ok=not issues, issues=issues)
