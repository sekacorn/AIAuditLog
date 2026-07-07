# AIAuditLog

AIAuditLog provides portable, privacy-aware, tamper-evident evidence for AI
models, agents, tools, policies, reviews, and workflow outcomes.

This is an alpha release candidate for `0.1.0a3`. It is ready for public alpha
release with documented limitations, not production certification.

## Why AI Audit Logs Are Different

Ordinary application logs usually explain what software printed while it ran.
AI audit evidence must also preserve model choices, tool access, policy
decisions, human approvals, data references, redaction decisions, and workflow
outcomes in a vendor-neutral format that survives framework and provider
changes.

## Problem Statement

Organizations need inspectable evidence of what an AI system did, why it acted,
which models and policies were involved, what data and tools were accessed, and
what outcome occurred. AIAuditLog keeps that evidence local-first, append
oriented, deterministic, and suitable for CI review.

## Ecosystem Position

AIAuditLog is project six in the sekacorn AI infrastructure roadmap. It is
designed for future optional integration with Forge, PrivateAIStack,
ModelSwapBench, OpenOntologyLite, AgentPolicyPack, and OpenAIMeter. The first
alpha works independently and offline.

## Core Capabilities

- Versioned JSON event envelope and JSON Schema export.
- Typed Python models for AI, agent, tool, policy, ontology, and benchmark context.
- RFC8785-backed canonical JSON after AIAuditLog value normalization.
- SHA-256 event digests.
- Optional hash-chain metadata for tamper evidence.
- Checkpoints, optional Ed25519 checkpoint signatures, and signature policies.
- JSONL storage and SQLite indexing.
- Stream rotation, lock-file guarded appends, compressed exports, and schema migration helpers.
- Privacy modes, deterministic redaction, secret-key filtering, classification redaction, and CSV-safe export.
- CLI and Python API.
- Neutral adapter protocols for future ecosystem packages.

## Event Architecture

Each event contains `schema_version`, `event_id`, `event_type`, UTC
`event_time`, UTC `recorded_time`, `source`, `actor`, `outcome`, `data`,
optional context, and `integrity`. Core event types cover system, agent, model,
tool, data, retrieval, policy, review, security, evaluation, benchmark, and
audit-log lifecycle categories. Custom event types must be namespaced and may
not collide with reserved core namespaces.

## Installation

```powershell
python -m pip install aiauditlog
```

For development:

```powershell
python -m pip install -e ".[dev]"
```

## Quick Start

```powershell
aiaudit validate examples/basic/event.json
aiaudit append build/audit.jsonl --event examples/basic/event.json
aiaudit verify build/audit.jsonl
aiaudit summarize build/audit.jsonl
```

## JSON Event Example

See `examples/basic/event.json` for a complete model invocation event. Prompts
and responses are not stored by default; use hashes, references, counts, and
explicitly configured safe excerpts.

## Recorder Example

```python
from ai_audit_log import AuditRecorder, EventBuilder, JsonlStore, Outcome, Source
from ai_audit_log.models import Actor

builder = EventBuilder(
    source=Source(service="claims-agent"),
    actor=Actor(actor_id="agent-17", actor_type="ai_agent"),
)
recorder = AuditRecorder(builder=builder, store=JsonlStore("build/audit.jsonl"))
recorder.record(
    event_type="model.invocation.completed",
    outcome=Outcome(status="success", code="COMPLETED"),
    data={"provider": "example", "model_name": "example-model"},
)
```

## Chain Verification

```powershell
aiaudit verify build/audit.jsonl
```

Hash chaining is tamper-evident, not immutable. An attacker who can rewrite an
entire unsigned log can recompute the chain.

## Privacy Modes

The default mode is `minimal`: identifiers, metadata, hashes, counts, outcomes,
and policy evidence are preserved, while prompts, responses, and common secret
keys are redacted. `balanced` may keep short configured excerpts.
`full-content` requires explicit opt-in and can expose sensitive data.

## Checkpoints And Signatures

Checkpoints summarize stream ID, event count, terminal digest, and checkpoint
digest. Ed25519 signatures authenticate the checkpoint bytes to a public key,
and checkpoint signature policies can require allowed key IDs, fingerprints, and
minimum signature counts. Signatures do not prove real-world actor identity,
legal non-repudiation, or correct key custody.

```powershell
aiaudit checkpoint create build/audit.jsonl --output build/checkpoint.json
aiaudit key generate --private-key build/development-private.pem --public-key build/development-public.pem
aiaudit sign build/checkpoint.json --private-key build/development-private.pem --key-id development-key
aiaudit signature verify build/checkpoint.json --public-key build/development-public.pem
```

Never commit generated private keys.

## CLI Examples

```powershell
aiaudit inspect examples/basic/event.json
aiaudit query build/audit.jsonl --event-type model.invocation.completed
aiaudit export build/audit.jsonl --format markdown --output build/audit-report.md --compress
aiaudit redact build/audit.jsonl --profile examples/privacy/minimal.yaml --output build/audit-redacted.jsonl
aiaudit migrate examples/basic/legacy-event.json --output build/migrated-event.json
aiaudit rotate build/audit.jsonl
aiaudit schema list
aiaudit schema export --output build/schemas
```

## Storage

JSONL is the canonical local stream format. SQLite indexing is optional and is
not tamper-proof; chain verification recalculates event digests from stored
events.

## Adapters

The package includes neutral protocols for framework, policy, ontology, and
benchmark adapters. No external ecosystem package is required in core.

## Security Model

AIAuditLog distinguishes application logs, telemetry, audit evidence,
cryptographic integrity, authenticity, non-repudiation, and legal
admissibility. It provides local tamper evidence and optional checkpoint
signatures. It does not provide immutable storage, identity proofing, legal
certification, a SIEM, or policy enforcement.

## Threat Model And Limitations

- Hash chaining is tamper-evident, not immutable.
- An attacker who can rewrite the entire log may recompute an unsigned chain.
- Signatures depend on secure key custody.
- The package does not establish real-world actor identity.
- Timestamps depend on system clocks.
- Local storage can be deleted.
- SQLite is not tamper-proof.
- Full-content logging may expose sensitive data.
- Redaction and secret detection are heuristic and not perfect.
- Adapters depend on external framework APIs.
- Event completeness depends on correct instrumentation.
- Missing events cannot always be distinguished from actions that never occurred.
- Audit records do not guarantee model correctness.
- Audit records do not enforce policy.
- Compliance mappings are informational.
- This project is not legal advice.
- The schema may evolve before version 1.0.
- External anchoring and trusted timestamping are not included in this alpha.
- Concurrent multi-process writing has documented limitations unless explicitly tested.

## Interoperability

Canonical JSON serialization uses the maintained `rfc8785` package after
AIAuditLog normalizes datetimes, Decimals, bytes, and model objects. Timestamps
are RFC 3339-compatible UTC strings. Trace and span fields can carry W3C Trace
Context or OpenTelemetry identifiers, and helper functions can parse and emit
`traceparent` values. CloudEvents concepts influenced envelope naming, but this
package does not claim CloudEvents compliance.

## Roadmap

Implemented in 0.1.0a2:

- RFC8785-backed canonicalization with an RFC8785 sample vector.
- Signed checkpoint policies.
- Stream rotation.
- Deterministic gzip exports.
- Richer privacy profiles.
- Lock-file guarded appends.
- Conservative schema migration helpers.

Implemented in 0.1.0a3:

- Neutral Forge-like agent step adapter.
- Neutral AgentPolicyPack-like policy decision adapter.
- Neutral ModelSwapBench-like benchmark context adapter.
- Neutral OpenOntologyLite-like ontology context adapter.
- Neutral PrivateAIStack metadata adapter.
- OpenTelemetry/W3C Trace Context helpers.

The 0.1.0a3 adapters intentionally use plain dictionaries and are not claimed as
externally tested against sibling packages.

Next candidates for 0.1.0a4:

- Broader export test coverage for JSON, JSONL, CSV, Markdown, and compressed outputs.
- Signed stream manifests.
- Stronger rotation manifests and rotation verification.
- More complete schema migration fixtures.
- Optional dependency-license report generation.
- Improved concurrent-writer stress tests.

0.2 candidates:

- External checkpoint anchoring.
- Optional PostgreSQL storage.
- Retention policies.
- Audit package bundles.
- Provenance attestations.
- Organization-specific event profiles.
- SIEM exporters.

1.0 considerations:

- Stable schema.
- Compatibility policy.
- Formal canonicalization profile.
- Migration policy.
- Interoperability test suite.
- Independent security review.

## Contributing

Use the development commands in `docs/getting-started.md`. Keep claims
verifiable and do not commit secrets, private keys, local audit logs, databases,
or generated distribution artifacts.

## License

MIT.

## Author

sekacorn
