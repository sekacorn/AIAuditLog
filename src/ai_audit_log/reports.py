"""Inspection and human-readable reports."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ai_audit_log.chain import ChainReport
from ai_audit_log.models import AuditEvent


def inspect_event(event: AuditEvent) -> dict[str, object]:
    """Return a compact inspection dictionary."""

    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "event_time": event.event_time.isoformat(),
        "recorded_time": event.recorded_time.isoformat(),
        "source": event.source.model_dump(exclude_none=True),
        "actor": event.actor.model_dump(exclude_none=True),
        "outcome": event.outcome.model_dump(exclude_none=True),
        "integrity": event.integrity.model_dump(exclude_none=True),
    }


def summarize_events(events: list[AuditEvent]) -> dict[str, Any]:
    """Summarize events by type and outcome."""

    return {
        "event_count": len(events),
        "event_types": dict(Counter(event.event_type for event in events)),
        "outcomes": dict(Counter(event.outcome.status for event in events)),
        "streams": sorted({event.integrity.stream_id for event in events if event.integrity.stream_id}),
    }


def markdown_report(events: list[AuditEvent], chain_report: ChainReport | None = None) -> str:
    """Create a Markdown audit report."""

    summary = summarize_events(events)
    lines = [
        "# AIAuditLog Report",
        "",
        f"Event count: {summary['event_count']}",
        "",
        "## Outcomes",
    ]
    for status, count in sorted(summary["outcomes"].items()):
        lines.append(f"- {status}: {count}")
    lines.extend(["", "## Event Types"])
    for event_type, count in sorted(summary["event_types"].items()):
        lines.append(f"- `{event_type}`: {count}")
    if chain_report is not None:
        lines.extend(
            [
                "",
                "## Chain",
                f"- OK: {chain_report.ok}",
                f"- Stream: {chain_report.stream_id}",
                f"- Terminal digest: `{chain_report.terminal_digest}`",
            ]
        )
        for issue in chain_report.issues:
            lines.append(f"- Issue {issue.index}: {issue.code} - {issue.message}")
    lines.extend(["", "## Events"])
    for event in events:
        digest = event.integrity.event_digest or ""
        lines.append(f"- `{event.event_type}` `{event.event_id}` `{event.outcome.status}` `{digest}`")
    return "\n".join(lines) + "\n"
