# Interoperability

AIAuditLog uses RFC 3339-compatible UTC timestamps and fields for W3C Trace
Context or OpenTelemetry trace and span identifiers. CloudEvents influenced the
envelope concept, but 0.1.0a1 does not claim CloudEvents compliance.

Supply-chain provenance concepts influenced checkpoint and digest reporting, but
the project does not claim SLSA, in-toto, or SPDX compliance.

Adapter protocols are prepared for Forge, AgentPolicyPack, ModelSwapBench,
OpenOntologyLite, PrivateAIStack, and OpenAIMeter. No adapter is claimed as
externally tested in this alpha.

The `ai_audit_log.ecosystem` module adds neutral dictionary adapters for:

- Forge-like agent step records.
- AgentPolicyPack-like policy decisions.
- ModelSwapBench-like benchmark results.
- OpenOntologyLite-like ontology context.
- PrivateAIStack-like deployment metadata.

These adapters intentionally accept plain dictionaries and do not import the
external packages. OpenTelemetry/W3C Trace Context helpers live in
`ai_audit_log.otel`.
