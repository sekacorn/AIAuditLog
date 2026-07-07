"""JSON Schema export."""

from __future__ import annotations

import json
from pathlib import Path

from ai_audit_log.models import AuditEvent


def schema_names() -> list[str]:
    """Return packaged schema names."""

    return ["audit-event-v1"]


def audit_event_schema() -> dict[str, object]:
    """Return the AuditEvent JSON Schema."""

    return AuditEvent.model_json_schema()


def export_schemas(output: str | Path) -> None:
    """Export schemas to a directory."""

    path = Path(output)
    path.mkdir(parents=True, exist_ok=True)
    (path / "audit-event-v1.schema.json").write_text(
        json.dumps(audit_event_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
