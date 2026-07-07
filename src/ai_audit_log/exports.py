"""Export helpers."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ai_audit_log.chain import ChainVerifier
from ai_audit_log.compression import gzip_file
from ai_audit_log.models import AuditEvent
from ai_audit_log.privacy import PrivacyProfile, redact_value, redaction_manifest
from ai_audit_log.reports import markdown_report


def escape_csv(value: object) -> str:
    """Escape CSV formula-looking strings."""

    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


def export_events(
    events: list[AuditEvent],
    *,
    fmt: str,
    output: str | Path,
    privacy_profile: PrivacyProfile | None = None,
    compress: bool = False,
) -> None:
    """Export events to JSONL, JSON, CSV, or Markdown."""

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    docs = [event.model_dump(mode="json", exclude_none=True) for event in events]
    if privacy_profile is not None:
        docs = [redact_value(doc, privacy_profile) for doc in docs]
    if fmt == "jsonl":
        path.write_text("\n".join(json.dumps(doc, sort_keys=True) for doc in docs) + "\n", encoding="utf-8")
    elif fmt == "json":
        path.write_text(json.dumps(docs, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif fmt == "csv":
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["event_id", "event_type", "recorded_time", "status", "digest"])
            for event in events:
                writer.writerow(
                    [
                        escape_csv(event.event_id),
                        escape_csv(event.event_type),
                        escape_csv(event.recorded_time.isoformat()),
                        escape_csv(event.outcome.status),
                        escape_csv(event.integrity.event_digest),
                    ]
                )
    elif fmt == "markdown":
        path.write_text(markdown_report(events, ChainVerifier().verify(events)), encoding="utf-8")
    else:
        raise ValueError("unsupported export format")

    if compress:
        gzip_file(path)

    if privacy_profile is not None:
        manifest = {
            "format": fmt,
            "event_count": len(events),
            "redaction": redaction_manifest(privacy_profile),
        }
        path.with_suffix(path.suffix + ".manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
