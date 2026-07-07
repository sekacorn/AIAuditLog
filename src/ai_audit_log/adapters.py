"""Framework-neutral adapter protocols."""

from __future__ import annotations

from typing import Any, Protocol

from ai_audit_log.models import AuditEvent


class EventAdapter(Protocol):
    """Protocol for turning framework-native records into audit events."""

    def to_audit_event(self, value: Any) -> AuditEvent:
        """Convert a framework record into an AuditEvent."""


class PolicyDecisionAdapter(Protocol):
    """Protocol prepared for AgentPolicyPack-style decisions."""

    def decision_payload(self, value: Any) -> dict[str, Any]:
        """Return a policy payload dictionary."""


class OntologyContextAdapter(Protocol):
    """Protocol prepared for OpenOntologyLite-style context."""

    def ontology_context(self, value: Any) -> dict[str, Any]:
        """Return ontology context."""


class BenchmarkContextAdapter(Protocol):
    """Protocol prepared for ModelSwapBench-style context."""

    def benchmark_context(self, value: Any) -> dict[str, Any]:
        """Return benchmark context."""
