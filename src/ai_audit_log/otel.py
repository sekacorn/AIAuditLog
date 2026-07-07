"""OpenTelemetry and W3C Trace Context helpers."""

from __future__ import annotations

import re

from ai_audit_log.models import Correlation

TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-(?P<span_id>[0-9a-f]{16})-(?P<trace_flags>[0-9a-f]{2})$"
)


def correlation_from_traceparent(traceparent: str) -> Correlation:
    """Create correlation metadata from a W3C traceparent header."""

    match = TRACEPARENT_RE.fullmatch(traceparent.strip().lower())
    if match is None:
        raise ValueError("invalid traceparent")
    return Correlation(trace_id=match.group("trace_id"), span_id=match.group("span_id"))


def traceparent_from_correlation(correlation: Correlation, *, sampled: bool = True) -> str:
    """Create a traceparent value from correlation metadata."""

    if correlation.trace_id is None or correlation.span_id is None:
        raise ValueError("trace_id and span_id are required")
    flags = "01" if sampled else "00"
    return f"00-{correlation.trace_id.lower()}-{correlation.span_id.lower()}-{flags}"
