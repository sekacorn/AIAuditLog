"""Typed event envelope and payload models."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from ai_audit_log.constants import (
    CLASSIFICATIONS,
    CORE_EVENT_TYPES,
    OUTCOME_STATUSES,
    RESERVED_NAMESPACES,
    SCHEMA_VERSION,
)
from ai_audit_log.ids import validate_event_id
from ai_audit_log.time import format_rfc3339, parse_rfc3339, require_aware_utc

JsonObject = dict[str, Any]


class StrictModel(BaseModel):
    """Base model with strict assignment and no undeclared fields."""

    model_config = ConfigDict(extra="forbid", frozen=False, validate_assignment=True)


class PayloadModel(BaseModel):
    """Payload model that validates known fields while preserving extensions."""

    model_config = ConfigDict(extra="allow", frozen=False, validate_assignment=True)


class Source(StrictModel):
    """Origin of an audit event."""

    service: str
    component: str | None = None
    instance_id: str | None = None
    environment: str | None = None
    version: str | None = None


class Actor(StrictModel):
    """Actor represented by an audit event."""

    actor_id: str
    actor_type: str
    roles: list[str] = Field(default_factory=list)
    delegated_by: str | None = None
    session_id: str | None = None


class Subject(StrictModel):
    """Subject affected by an event."""

    subject_type: str | None = None
    subject_id: str | None = None
    classification: str | None = None

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, value: str | None) -> str | None:
        if value is not None and value not in CLASSIFICATIONS and "." not in value:
            raise ValueError("custom classifications must be namespaced")
        return value


class Correlation(StrictModel):
    """Correlation identifiers from workflows, traces, and parent events."""

    request_id: str | None = None
    workflow_id: str | None = None
    run_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    parent_event_id: str | None = None


class Outcome(StrictModel):
    """Stable event outcome."""

    status: str
    code: str
    reason: str | None = None
    error_type: str | None = None
    retryable: bool | None = None
    http_status: int | None = None
    provider_code: str | None = None
    details: JsonObject = Field(default_factory=dict)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in OUTCOME_STATUSES:
            raise ValueError(f"unsupported outcome status: {value}")
        return value


class Integrity(StrictModel):
    """Digest, chain, and signature metadata."""

    stream_id: str | None = None
    sequence: int | None = None
    previous_event_digest: str | None = None
    event_digest: str | None = None
    digest_algorithm: str | None = None
    chain_algorithm: str | None = None
    signatures: list[JsonObject] = Field(default_factory=list)


class Classification(StrictModel):
    """Event classification metadata."""

    event: str | None = None
    payload: str | None = None
    highest: str | None = None
    handling: list[str] = Field(default_factory=list)


class ModelInvocationPayload(PayloadModel):
    """Payload fields for model invocation and routing events."""

    provider: str | None = None
    model_name: str | None = None
    model_version: str | None = None
    endpoint_classification: str | None = None
    hosting_mode: str | None = None
    is_external: bool | None = None
    request_purpose: str | None = None
    prompt_template_id: str | None = None
    prompt_hash: str | None = None
    response_hash: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_tokens: int | None = None
    latency_ms: int | None = None
    estimated_cost: Decimal | None = None
    actual_cost: Decimal | None = None
    retry_number: int | None = None
    temperature: Decimal | None = None
    parameters: JsonObject = Field(default_factory=dict)
    finish_reason: str | None = None
    structured_output_schema_id: str | None = None
    validation_result: str | None = None
    routing_reason: str | None = None
    fallback: JsonObject = Field(default_factory=dict)
    prompt_excerpt: str | None = None
    response_excerpt: str | None = None


class ToolCallPayload(PayloadModel):
    """Payload fields for tool-call events."""

    tool_name: str | None = None
    tool_namespace: str | None = None
    tool_version: str | None = None
    capability: str | None = None
    risk_classification: str | None = None
    arguments_hash: str | None = None
    argument_summary: str | None = None
    result_hash: str | None = None
    result_summary: str | None = None
    target_resource: str | None = None
    policy_decision: str | None = None
    human_approval: str | None = None
    duration_ms: int | None = None
    status: str | None = None
    side_effect: str | None = None
    retry_number: int | None = None
    sandbox: JsonObject = Field(default_factory=dict)


class AgentPayload(PayloadModel):
    """Payload fields for agent lifecycle and step events."""

    agent_id: str | None = None
    agent_type: str | None = None
    framework: str | None = None
    role: str | None = None
    supervisor_id: str | None = None
    parent_agent_id: str | None = None
    delegated_authority: str | None = None
    objective_hash: str | None = None
    objective_summary: str | None = None
    step_number: int | None = None
    plan_id: str | None = None
    memory_references: list[str] = Field(default_factory=list)
    tool_count: int | None = None
    model_call_count: int | None = None
    budget: JsonObject = Field(default_factory=dict)
    accumulated_cost: Decimal | None = None
    completion_reason: str | None = None
    failure_reason: str | None = None


class PolicyPayload(PayloadModel):
    """Payload fields for policy and governance events."""

    policy_engine: str | None = None
    bundle_id: str | None = None
    bundle_version: str | None = None
    bundle_digest: str | None = None
    decision_id: str | None = None
    final_decision: str | None = None
    matched_policies: list[str] = Field(default_factory=list)
    controlling_policy: str | None = None
    conflict_strategy: str | None = None
    obligations: list[JsonObject] = Field(default_factory=list)
    effective_limits: JsonObject = Field(default_factory=dict)
    evidence_digest: str | None = None
    reason: str | None = None
    missing_context: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    review_requirements: list[str] = Field(default_factory=list)


class OntologyContext(StrictModel):
    """Optional OpenOntologyLite-compatible context."""

    ontology_id: str | None = None
    ontology_version: str | None = None
    ontology_digest: str | None = None
    entity_type: str | None = None
    entity_id: str | None = None
    action_name: str | None = None
    relationship_context: JsonObject = Field(default_factory=dict)
    namespace: str | None = None


class BenchmarkContext(StrictModel):
    """Optional ModelSwapBench-compatible context."""

    benchmark_id: str | None = None
    benchmark_version: str | None = None
    case_id: str | None = None
    run_id: str | None = None
    provider: str | None = None
    model: str | None = None
    evaluator_results: JsonObject = Field(default_factory=dict)
    success: bool | None = None
    cost_per_successful_outcome: Decimal | None = None
    replacement_decision: str | None = None
    cascade_decision: str | None = None


class AuditEvent(StrictModel):
    """Common event envelope for AIAuditLog."""

    schema_version: str = SCHEMA_VERSION
    event_id: str
    event_type: str
    event_time: datetime
    recorded_time: datetime
    source: Source
    actor: Actor
    subject: Subject | None = None
    correlation: Correlation = Field(default_factory=Correlation)
    outcome: Outcome
    classification: Classification = Field(default_factory=Classification)
    data: JsonObject = Field(default_factory=dict)
    policy: JsonObject = Field(default_factory=dict)
    ontology: OntologyContext | None = None
    benchmark: BenchmarkContext | None = None
    integrity: Integrity = Field(default_factory=Integrity)
    extensions: JsonObject = Field(default_factory=dict)

    @field_validator("event_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return validate_event_id(value)

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if value in CORE_EVENT_TYPES:
            return value
        parts = value.split(".")
        if len(parts) < 3:
            raise ValueError("custom event types must be namespaced")
        if parts[0] in RESERVED_NAMESPACES:
            raise ValueError("custom event type collides with a reserved namespace")
        return value

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError("unsupported schema_version")
        return value

    @field_validator("event_time", "recorded_time", mode="before")
    @classmethod
    def parse_time(cls, value: datetime | str) -> datetime:
        if isinstance(value, str):
            return parse_rfc3339(value)
        return require_aware_utc(value)

    @field_serializer("event_time", "recorded_time")
    def serialize_time(self, value: datetime) -> str:
        return format_rfc3339(value)

    @model_validator(mode="after")
    def validate_sequence_consistency(self) -> AuditEvent:
        if self.integrity.sequence is not None and self.integrity.sequence < 1:
            raise ValueError("sequence must begin at 1")
        return self


def payload_for_event(event_type: str, payload: JsonObject) -> BaseModel | None:
    """Validate a known typed payload and return its model instance."""

    if event_type.startswith("model."):
        return ModelInvocationPayload.model_validate(payload)
    if event_type.startswith("tool."):
        return ToolCallPayload.model_validate(payload)
    if event_type.startswith("agent."):
        return AgentPayload.model_validate(payload)
    if event_type.startswith("policy."):
        return PolicyPayload.model_validate(payload)
    return None
