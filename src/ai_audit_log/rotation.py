"""Stream rotation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ai_audit_log.models import AuditEvent
from ai_audit_log.storage import JsonlStore


@dataclass(frozen=True)
class RotationPolicy:
    """Size and count thresholds for JSONL stream rotation."""

    max_bytes: int | None = None
    max_events: int | None = None
    suffix_width: int = 4


@dataclass(frozen=True)
class RotationDecision:
    """Decision returned before appending an event."""

    should_rotate: bool
    reason: str | None = None
    next_path: Path | None = None


def rotation_decision(
    path: str | Path,
    policy: RotationPolicy,
    *,
    next_event: AuditEvent | None = None,
) -> RotationDecision:
    """Return whether a stream should rotate before the next append."""

    active_path = Path(path)
    if policy.max_bytes is not None and active_path.exists():
        size = active_path.stat().st_size
        if next_event is not None:
            size += len(next_event.model_dump_json(exclude_none=True).encode()) + 1
        if size > policy.max_bytes:
            return RotationDecision(True, "max_bytes", next_rotated_path(active_path, policy.suffix_width))
    if policy.max_events is not None and active_path.exists():
        count = len(JsonlStore(active_path).read_all())
        if count + (1 if next_event is not None else 0) > policy.max_events:
            return RotationDecision(True, "max_events", next_rotated_path(active_path, policy.suffix_width))
    return RotationDecision(False)


def next_rotated_path(path: str | Path, suffix_width: int = 4) -> Path:
    """Return the next available numbered rotation path."""

    active_path = Path(path)
    for index in range(1, 10000):
        candidate = active_path.with_name(f"{active_path.name}.{index:0{suffix_width}d}")
        if not candidate.exists():
            return candidate
    raise RuntimeError("no rotation suffix available")


def rotate_stream(path: str | Path, policy: RotationPolicy | None = None) -> Path:
    """Rename the active stream to the next rotation path and return it."""

    active_policy = policy or RotationPolicy()
    active_path = Path(path)
    rotated = next_rotated_path(active_path, active_policy.suffix_width)
    active_path.rename(rotated)
    return rotated
