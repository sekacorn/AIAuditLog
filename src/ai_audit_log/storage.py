"""JSONL storage and SQLite indexing."""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ai_audit_log.models import AuditEvent


@contextmanager
def file_lock(path: Path, *, timeout_seconds: float = 10.0) -> Iterator[None]:
    """Create a simple cross-process lock file around critical JSONL writes."""

    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    handle: int | None = None
    # This is a local filesystem coordination primitive. It protects the
    # read-chain-write sequence for cooperating writers, not remote storage.
    while handle is None:
        try:
            handle = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for lock: {lock_path}") from None
            time.sleep(0.05)
    try:
        yield
    finally:
        os.close(handle)
        lock_path.unlink(missing_ok=True)


class JsonlStore:
    """Append-oriented JSONL event storage."""

    def __init__(
        self,
        path: str | Path,
        *,
        fsync: bool = False,
        max_line_bytes: int = 2_000_000,
        use_lock: bool = False,
    ) -> None:
        self.path = Path(path)
        self.fsync = fsync
        self.max_line_bytes = max_line_bytes
        self.use_lock = use_lock

    def append(self, event: AuditEvent) -> None:
        """Append one event as a newline-terminated JSON object."""

        line = self._event_line(event)
        if self.use_lock:
            with file_lock(self.path):
                self._append_line(line)
            return
        self._append_line(line)

    def append_chained(self, event: AuditEvent, *, stream_id: str) -> AuditEvent:
        """Append one event while holding the lock across read, chain, and write."""

        if not self.use_lock:
            raise ValueError("append_chained requires JsonlStore(use_lock=True)")
        from ai_audit_log.chain import append_integrity

        with file_lock(self.path):
            existing = self.read_all()
            previous = existing[-1].integrity.event_digest if existing else None
            chained = append_integrity(
                event,
                stream_id=stream_id,
                sequence=len(existing) + 1,
                previous_event_digest=previous,
            )
            self._append_line(self._event_line(chained))
            return chained

    def _event_line(self, event: AuditEvent) -> str:
        line = event.model_dump_json(exclude_none=True)
        if len(line.encode()) > self.max_line_bytes:
            raise ValueError("event line exceeds configured maximum")
        return line

    def _append_line(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.write("\n")
            handle.flush()
            if self.fsync:
                os.fsync(handle.fileno())

    def read_all(self) -> list[AuditEvent]:
        """Read all complete JSONL events."""

        if not self.path.exists():
            return []
        events: list[AuditEvent] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.endswith("\n"):
                    raise ValueError(f"incomplete final line at {line_number}")
                stripped = line.strip()
                if not stripped:
                    continue
                if len(stripped.encode("utf-8")) > self.max_line_bytes:
                    raise ValueError(f"line {line_number} exceeds configured maximum")
                events.append(AuditEvent.model_validate_json(stripped))
        return events

    def write_all(self, events: Iterable[AuditEvent]) -> None:
        """Replace the file with a complete JSONL stream."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8", newline="\n") as handle:
            for event in events:
                handle.write(event.model_dump_json(exclude_none=True))
                handle.write("\n")


class SQLiteIndex:
    """SQLite index for querying JSONL-backed event streams."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        """Open a SQLite connection."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        """Create the index schema."""

        connection = self.connect()
        try:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        event_time TEXT NOT NULL,
                        recorded_time TEXT NOT NULL,
                        stream_id TEXT,
                        sequence INTEGER,
                        event_digest TEXT,
                        status TEXT NOT NULL,
                        canonical_event TEXT NOT NULL
                    )
                    """
                )
                connection.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
                connection.execute("CREATE INDEX IF NOT EXISTS idx_events_stream_seq ON events(stream_id, sequence)")
        finally:
            connection.close()

    def append(self, event: AuditEvent) -> None:
        """Insert or replace one event index row."""

        self.initialize()
        connection = self.connect()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO events
                    (event_id, event_type, event_time, recorded_time, stream_id, sequence,
                     event_digest, status, canonical_event)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.event_type,
                        event.event_time.isoformat(),
                        event.recorded_time.isoformat(),
                        event.integrity.stream_id,
                        event.integrity.sequence,
                        event.integrity.event_digest,
                        event.outcome.status,
                        event.model_dump_json(exclude_none=True),
                    ),
                )
        finally:
            connection.close()

    def rebuild(self, events: Iterable[AuditEvent]) -> None:
        """Rebuild the SQLite index from events."""

        self.initialize()
        connection = self.connect()
        try:
            with connection:
                connection.execute("DELETE FROM events")
        finally:
            connection.close()
        for event in events:
            self.append(event)

    def query(self, **filters: Any) -> list[AuditEvent]:
        """Query with parameterized filters."""

        self.initialize()
        clauses: list[str] = []
        params: list[Any] = []
        mapping = {
            "event_type": "event_type = ?",
            "status": "status = ?",
            "stream_id": "stream_id = ?",
        }
        for key, clause in mapping.items():
            value = filters.get(key)
            if value is not None:
                clauses.append(clause)
                params.append(value)
        limit = int(filters.get("limit", 100))
        base_sql = "SELECT canonical_event FROM events"
        order_limit_sql = " ORDER BY recorded_time, event_id LIMIT ?"
        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = base_sql + where_sql + order_limit_sql
        params.append(limit)
        connection = self.connect()
        try:
            rows = connection.execute(sql, params).fetchall()
        finally:
            connection.close()
        return [AuditEvent.model_validate_json(str(row["canonical_event"])) for row in rows]
