"""Checkpoint creation and verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import Field, ValidationError, field_validator, model_validator

from ai_audit_log.chain import ChainVerifier
from ai_audit_log.constants import CHAIN_ALGORITHM, DIGEST_ALGORITHM, SCHEMA_VERSION
from ai_audit_log.digest import is_sha256_digest, sha256_digest
from ai_audit_log.exceptions import IntegrityError
from ai_audit_log.models import AuditEvent, StrictModel
from ai_audit_log.time import format_rfc3339, now_utc, parse_rfc3339

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from ai_audit_log.checkpoint_policy import CheckpointPolicyResult, CheckpointSignaturePolicy


class Checkpoint(StrictModel):
    """Signed or unsigned stream checkpoint."""

    schema_version: str = SCHEMA_VERSION
    stream_id: str
    event_count: int
    terminal_digest: str | None
    chain_algorithm: str = CHAIN_ALGORITHM
    digest_algorithm: str = DIGEST_ALGORITHM
    created_time: str = Field(default_factory=lambda: format_rfc3339(now_utc()))
    checkpoint_digest: str | None = None
    signatures: list[dict[str, Any]] = Field(default_factory=list)

    def unsigned_payload(self) -> dict[str, Any]:
        """Return checkpoint data covered by its digest."""

        payload = self.model_dump(exclude_none=True)
        payload.pop("checkpoint_digest", None)
        payload.pop("signatures", None)
        # Checkpoints created before digest_algorithm was introduced remain
        # verifiable against the payload they originally signed.
        if "digest_algorithm" not in self.model_fields_set:
            payload.pop("digest_algorithm", None)
        return payload

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint schema_version")
        return value

    @field_validator("chain_algorithm")
    @classmethod
    def validate_chain_algorithm(cls, value: str) -> str:
        if value != CHAIN_ALGORITHM:
            raise ValueError("unsupported checkpoint chain_algorithm")
        return value

    @field_validator("digest_algorithm")
    @classmethod
    def validate_digest_algorithm(cls, value: str) -> str:
        if value != DIGEST_ALGORITHM:
            raise ValueError("unsupported checkpoint digest_algorithm")
        return value

    @field_validator("created_time")
    @classmethod
    def validate_created_time(cls, value: str) -> str:
        return format_rfc3339(parse_rfc3339(value))

    @field_validator("terminal_digest", "checkpoint_digest")
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and not is_sha256_digest(value):
            raise ValueError("checkpoint digest must be a formatted SHA-256 digest")
        return value

    @field_validator("event_count", mode="before")
    @classmethod
    def validate_event_count_type(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("checkpoint event_count must be an integer")
        return value

    @field_validator("signatures")
    @classmethod
    def validate_signatures(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        required = {"algorithm", "key_id", "public_key_fingerprint", "signature"}
        for record in value:
            if set(record) != required or any(not isinstance(record[key], str) for key in required):
                raise ValueError("checkpoint signatures must use the supported record schema")
        return value

    @model_validator(mode="after")
    def validate_consistency(self) -> Checkpoint:
        if not self.stream_id.strip():
            raise ValueError("checkpoint stream_id must not be empty")
        if isinstance(self.event_count, bool) or self.event_count < 0:
            raise ValueError("checkpoint event_count must be a non-negative integer")
        if self.event_count == 0 and self.terminal_digest is not None:
            raise ValueError("empty checkpoints must not include a terminal digest")
        if self.event_count > 0 and self.terminal_digest is None:
            raise ValueError("non-empty checkpoints require a terminal digest")
        return self


@dataclass(frozen=True)
class CheckpointResult:
    """Checkpoint verification result."""

    ok: bool
    issues: list[str]


@dataclass(frozen=True)
class SignedCheckpointResult:
    """Combined stream and signature verification result."""

    ok: bool
    checkpoint: CheckpointResult
    signatures: CheckpointPolicyResult | None


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
        digest_algorithm=DIGEST_ALGORITHM,
    )
    checkpoint.checkpoint_digest = sha256_digest(checkpoint.unsigned_payload())
    return checkpoint


def verify_checkpoint(checkpoint: Checkpoint, events: list[AuditEvent]) -> CheckpointResult:
    """Verify a checkpoint against a stream."""

    issues: list[str] = []
    issues.extend(checkpoint_structure_issues(checkpoint))
    issues.extend(verify_checkpoint_digest(checkpoint))
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


def verify_checkpoint_digest(checkpoint: Checkpoint) -> list[str]:
    """Verify the checkpoint's self-contained integrity binding."""

    calculated = sha256_digest(checkpoint.unsigned_payload())
    if checkpoint.checkpoint_digest != calculated:
        return ["checkpoint digest mismatch"]
    return []


def checkpoint_structure_issues(checkpoint: Checkpoint) -> list[str]:
    """Revalidate mutable checkpoint fields before accepting verification input."""

    try:
        Checkpoint.model_validate(checkpoint.model_dump(mode="python"))
    except ValidationError:
        return ["checkpoint structure invalid"]
    return []


def verify_signed_checkpoint(
    checkpoint: Checkpoint,
    events: list[AuditEvent],
    *,
    public_keys: dict[str, Ed25519PublicKey],
    policy: CheckpointSignaturePolicy | None = None,
) -> SignedCheckpointResult:
    """Verify stream integrity first, then evaluate checkpoint signatures."""

    from ai_audit_log.checkpoint_policy import verify_checkpoint_policy

    checkpoint_result = verify_checkpoint(checkpoint, events)
    if not checkpoint_result.ok:
        return SignedCheckpointResult(ok=False, checkpoint=checkpoint_result, signatures=None)
    signature_result = verify_checkpoint_policy(checkpoint, public_keys=public_keys, policy=policy)
    return SignedCheckpointResult(
        ok=signature_result.ok,
        checkpoint=checkpoint_result,
        signatures=signature_result,
    )
