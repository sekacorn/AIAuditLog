"""AIAuditLog exceptions."""


class AIAuditLogError(Exception):
    """Base class for package errors."""


class ValidationError(AIAuditLogError, ValueError):
    """Raised when an audit event is invalid."""


class CanonicalizationError(AIAuditLogError, ValueError):
    """Raised when a value cannot be canonicalized safely."""


class IntegrityError(AIAuditLogError):
    """Raised when digest or chain verification fails."""


class PrivacyError(AIAuditLogError):
    """Raised when privacy configuration is unsafe or invalid."""


class SignatureError(AIAuditLogError):
    """Raised when signing or signature verification fails."""
