"""Digest projection and SHA-256 hashing."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from ai_audit_log.canonical import canonical_json_bytes
from ai_audit_log.constants import DIGEST_ALGORITHM
from ai_audit_log.models import AuditEvent


def digest_projection(event: AuditEvent) -> dict[str, Any]:
    """Return the exact event projection covered by the event digest."""

    data = event.model_dump(mode="python", exclude_none=True)
    integrity = data.get("integrity", {})
    integrity.pop("event_digest", None)
    integrity.pop("signatures", None)
    if not integrity:
        data.pop("integrity", None)
    else:
        data["integrity"] = integrity
    return data


def sha256_digest(value: Any) -> str:
    """Return a formatted SHA-256 digest for a canonicalized value."""

    return f"{DIGEST_ALGORITHM}:{sha256(canonical_json_bytes(value)).hexdigest()}"


def event_digest(event: AuditEvent) -> str:
    """Calculate the event digest over the documented digest projection."""

    return sha256_digest(digest_projection(event))
