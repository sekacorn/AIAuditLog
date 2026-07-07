"""Schema migration helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ai_audit_log.constants import SCHEMA_VERSION


@dataclass(frozen=True)
class MigrationResult:
    """Migration result for one event document."""

    document: dict[str, Any]
    changed: bool
    warnings: list[str] = field(default_factory=list)


def migrate_event_document(document: dict[str, Any], *, target_schema_version: str = SCHEMA_VERSION) -> MigrationResult:
    """Migrate a JSON-like event document to the current alpha schema.

    This alpha helper intentionally supports only conservative field aliases
    observed in early examples. Unknown future schema versions fail closed.
    """

    source_version = str(document.get("schema_version", "0.1"))
    if source_version == target_schema_version:
        return MigrationResult(document=dict(document), changed=False)
    if source_version not in {"0.1", "1", "1.0-alpha"}:
        raise ValueError(f"unsupported source schema_version: {source_version}")

    migrated = dict(document)
    warnings: list[str] = []
    aliases = {
        "id": "event_id",
        "type": "event_type",
        "timestamp": "event_time",
        "recorded_at": "recorded_time",
        "payload": "data",
    }
    for old, new in aliases.items():
        if old in migrated and new not in migrated:
            migrated[new] = migrated.pop(old)
            warnings.append(f"renamed {old} to {new}")
    migrated["schema_version"] = target_schema_version
    return MigrationResult(document=migrated, changed=True, warnings=warnings)
