# Event Envelope

Required fields are `schema_version`, `event_id`, `event_type`, `event_time`,
`recorded_time`, `source`, `actor`, `outcome`, and `data`. Chained events also
include `integrity.stream_id`, `integrity.sequence`,
`integrity.previous_event_digest`, and `integrity.event_digest`.

Event IDs use UUID strings. Python 3.11 lacks a standard UUIDv7 generator, so
0.1.0a1 uses UUIDv4 for generated IDs and documents that generated IDs are
unique but not time-sortable. Externally supplied UUIDs are preserved.

Timestamps must be timezone-aware and are serialized as UTC RFC
3339-compatible strings with a `Z` suffix. Timestamps are not an ordering or
integrity mechanism.

Sequence numbers begin at `1`, increment by one within a stream, are included in
event digests, and are checked during chain verification.
