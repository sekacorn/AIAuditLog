# Security, Threat Model, And Limitations

AIAuditLog provides deterministic event digests, optional hash chaining, and
optional Ed25519 signatures over checkpoints. Hash chaining detects changes,
deletions, reordering, duplicate sequence values, sequence gaps, stream mixing,
and incorrect previous digests when the verifier has the events to inspect.

It does not make local files immutable. It does not prove who created an event.
It does not provide legal non-repudiation without independent identity and key
custody controls. It does not certify compliance.

Canonicalization normalizes AIAuditLog-specific Python values and then uses the
maintained `rfc8785` package for canonical JSON bytes. Tests include the RFC
8785 sample vector from the public reference material. Datetime, Decimal, bytes,
and model objects remain AIAuditLog-defined normalization steps before JCS.

Digest projection excludes the event's own digest and signatures. SHA-256 is
the required digest algorithm and digests are formatted as
`sha256:<lowercase-hex>`.

Privacy controls are deterministic but not perfect. Secret detection is based
on configurable key names and patterns. Full-content mode is explicit opt-in and
may expose sensitive data.

Checkpoint signature policies can require signatures, allowed key IDs, allowed
public-key fingerprints, and minimum signature counts. These policies verify
checkpoint signatures; they do not establish real-world identity or custody.
Signature verification also checks that a signature record's public-key
fingerprint matches the public key used for verification.

Development key generation refuses to overwrite existing key files unless the
caller passes `--force`. Generated private keys are unencrypted development
keys; production deployments should use their own key custody controls.
