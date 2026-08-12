# Security, Threat Model, And Limitations

AIAuditLog provides deterministic event digests, optional hash chaining, and
optional Ed25519 signatures over checkpoints. Hash chaining detects changes,
deletions, reordering, duplicate sequence values, sequence gaps, stream mixing,
incorrect previous digests, and unsupported declared chain or digest algorithms
when the verifier has the events to inspect.

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
may expose sensitive data. The redactor does not infer every credential or
personal datum embedded in arbitrary prose.

Events and profile files have practical limits on serialized size, nesting,
collection size, and string length. Privacy profile loading rejects duplicate
keys, YAML aliases, unsupported fields, and non-boolean flag coercion. These
limits reduce accidental and hostile resource consumption but are not a claim of
complete denial-of-service protection.

Checkpoint parsing rejects unknown fields and unsupported schema, digest, and
chain algorithms. Signature policies first verify the checkpoint digest, then
can require signatures, allowed key IDs, allowed public-key fingerprints, and
minimum signature counts. Complete verification additionally needs the
referenced event stream. These controls do not establish real-world identity or
custody.
Signature verification also checks that a signature record's public-key
fingerprint matches the public key used for verification.

Development key generation refuses to overwrite existing key files unless the
caller passes `--force`. Generated private keys are unencrypted development
keys; production deployments should use their own key custody controls.

`AuditRecorder` and `aiaudit append` use a local lock across chained read,
rotation, and write for cooperating writers. This does not protect against a
writer that bypasses the lock or against distributed or remote storage behavior.
Automatic rotated files each begin a new independent chain and must be verified
separately.
