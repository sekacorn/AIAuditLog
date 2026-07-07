# Python API

Primary imports:

```python
from ai_audit_log import AuditEvent, AuditRecorder, EventBuilder, JsonlStore, Outcome, Source
from ai_audit_log.models import Actor
```

Use `EventBuilder` to create validated privacy-filtered events, `AuditRecorder`
to append chained events, `JsonlStore` for JSONL streams, `SQLiteIndex` for
query indexing, `ChainVerifier` for integrity checks, and `Checkpoint` helpers
for stream summaries.

Additional alpha helpers:

- `ai_audit_log.rotation` for stream rotation policies.
- `ai_audit_log.compression` for deterministic gzip files.
- `ai_audit_log.migration` for conservative early-schema migration.
- `ai_audit_log.checkpoint_policy` for signed checkpoint policy checks.
- `ai_audit_log.otel` for W3C Trace Context correlation helpers.
- `ai_audit_log.ecosystem` for neutral dictionary adapters.
