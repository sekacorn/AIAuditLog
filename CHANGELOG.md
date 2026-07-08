# Changelog

All notable changes to AIAuditLog are documented here.

## 0.1.0a3 - Unreleased

- Add a versioned, typed audit-event envelope and packaged JSON Schema.
- Add RFC 8785-backed serialization after AIAuditLog-specific value normalization.
- Add SHA-256 event digests, optional hash chains, stream verification, and checkpoints.
- Add optional Ed25519 checkpoint signatures and signature policies.
- Add JSONL storage, optional SQLite indexing, querying, summaries, rotation, and migration helpers.
- Add privacy profiles, heuristic secret filtering and classification redaction.
- Add JSON, JSONL, CSV-safe, Markdown, redacted, and deterministic gzip exports.
- Add W3C Trace Context helpers and neutral dictionary-based ecosystem adapters.
- Add the `aiaudit` CLI and typed Python API.

This is alpha software. Hash chaining is tamper-evident, not immutable. Signatures
authenticate bytes to a key but do not prove real-world identity or legal
non-repudiation. Privacy filtering is heuristic. This release does not provide
automatic compliance, immutable storage, trusted timestamping, or external
anchoring. Neutral adapters have not been tested against sibling packages.
