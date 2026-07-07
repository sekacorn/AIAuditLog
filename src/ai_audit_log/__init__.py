"""Public Python API for AIAuditLog."""

from ai_audit_log.builder import EventBuilder
from ai_audit_log.chain import ChainVerifier, append_integrity
from ai_audit_log.checkpoint import Checkpoint
from ai_audit_log.checkpoint_policy import CheckpointSignaturePolicy, verify_checkpoint_policy
from ai_audit_log.compression import gzip_file
from ai_audit_log.digest import event_digest
from ai_audit_log.migration import MigrationResult, migrate_event_document
from ai_audit_log.models import AuditEvent, Outcome, Source
from ai_audit_log.otel import correlation_from_traceparent, traceparent_from_correlation
from ai_audit_log.privacy import PrivacyMode, PrivacyProfile, redact_value
from ai_audit_log.recorder import AuditRecorder
from ai_audit_log.rotation import RotationDecision, RotationPolicy
from ai_audit_log.signatures import Ed25519KeyPair
from ai_audit_log.storage import JsonlStore, SQLiteIndex

__all__ = [
    "AuditEvent",
    "AuditRecorder",
    "ChainVerifier",
    "Checkpoint",
    "CheckpointSignaturePolicy",
    "Ed25519KeyPair",
    "EventBuilder",
    "JsonlStore",
    "MigrationResult",
    "Outcome",
    "PrivacyMode",
    "PrivacyProfile",
    "RotationDecision",
    "RotationPolicy",
    "SQLiteIndex",
    "Source",
    "append_integrity",
    "correlation_from_traceparent",
    "event_digest",
    "gzip_file",
    "migrate_event_document",
    "redact_value",
    "traceparent_from_correlation",
    "verify_checkpoint_policy",
]

__version__ = "0.1.0a3"
