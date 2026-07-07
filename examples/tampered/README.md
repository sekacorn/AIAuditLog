# Tampered Fixture Notes

The tests generate tampered streams dynamically so the repository does not
ship confusing broken audit logs as examples. Tampering cases include modified
events, sequence gaps, stream mixing, and incorrect previous digests.
