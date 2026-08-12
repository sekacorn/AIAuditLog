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


def is_sha256_digest(value: str) -> bool:
    """Return whether a value has the supported formatted SHA-256 shape."""

    prefix = f"{DIGEST_ALGORITHM}:"
    if not value.startswith(prefix) or len(value) != len(prefix) + 64:
        return False
    try:
        int(value[len(prefix) :], 16)
    except ValueError:
        return False
    return True


def event_digest(event: AuditEvent) -> str:
    """Calculate the event digest over the documented digest projection."""

    return sha256_digest(digest_projection(event))
