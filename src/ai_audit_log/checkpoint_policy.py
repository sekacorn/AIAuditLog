"""Signed checkpoint policy verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_audit_log.checkpoint import Checkpoint
from ai_audit_log.signatures import public_key_fingerprint, verify_payload_signature


@dataclass(frozen=True)
class CheckpointSignaturePolicy:
    """Policy for required checkpoint signatures."""

    require_signature: bool = True
    allowed_key_ids: tuple[str, ...] = ()
    allowed_fingerprints: tuple[str, ...] = ()
    minimum_signatures: int = 1


@dataclass(frozen=True)
class CheckpointPolicyResult:
    """Result of checkpoint signature policy verification."""

    ok: bool
    issues: list[str] = field(default_factory=list)
    accepted_signatures: int = 0


def verify_checkpoint_policy(
    checkpoint: Checkpoint,
    *,
    public_keys: dict[str, Ed25519PublicKey],
    policy: CheckpointSignaturePolicy | None = None,
) -> CheckpointPolicyResult:
    """Verify checkpoint signatures against a simple allow-list policy."""

    active_policy = policy or CheckpointSignaturePolicy()
    issues: list[str] = []
    accepted = 0

    if active_policy.require_signature and not checkpoint.signatures:
        return CheckpointPolicyResult(ok=False, issues=["checkpoint has no signatures"])

    for record in checkpoint.signatures:
        key_id = str(record.get("key_id", ""))
        fingerprint = str(record.get("public_key_fingerprint", ""))
        if active_policy.allowed_key_ids and key_id not in active_policy.allowed_key_ids:
            issues.append(f"signature key_id not allowed: {key_id}")
            continue
        if active_policy.allowed_fingerprints and fingerprint not in active_policy.allowed_fingerprints:
            issues.append(f"signature fingerprint not allowed: {fingerprint}")
            continue
        public_key = public_keys.get(key_id)
        if public_key is None:
            issues.append(f"missing public key for key_id: {key_id}")
            continue
        if fingerprint and fingerprint != public_key_fingerprint(public_key):
            issues.append(f"signature fingerprint does not match public key: {key_id}")
            continue
        if _verify_one(checkpoint, record, public_key):
            accepted += 1

    if accepted < active_policy.minimum_signatures:
        issues.append("minimum signature count not satisfied")
    return CheckpointPolicyResult(ok=not issues, issues=issues, accepted_signatures=accepted)


def _verify_one(
    checkpoint: Checkpoint,
    record: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> bool:
    verify_payload_signature(checkpoint.unsigned_payload(), record, public_key)
    return True
