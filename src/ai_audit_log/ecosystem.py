"""Neutral helpers for planned sekacorn ecosystem integrations.

These helpers accept plain dictionaries so AIAuditLog can interoperate at the
data-boundary level without depending on sibling projects in core.
"""

from __future__ import annotations

from typing import Any

from ai_audit_log.builder import EventBuilder
from ai_audit_log.models import AuditEvent, BenchmarkContext, OntologyContext, Outcome


def forge_agent_step_event(
    record: dict[str, Any],
    *,
    builder: EventBuilder,
    event_type: str = "agent.step.completed",
) -> AuditEvent:
    """Create an event from a Forge-like agent step dictionary."""

    data = {
        "agent_id": record.get("agent_id"),
        "framework": record.get("framework", "forge"),
        "role": record.get("role"),
        "step_number": record.get("step_number"),
        "plan_id": record.get("plan_id"),
        "tool_count": record.get("tool_count"),
        "model_call_count": record.get("model_call_count"),
        "objective_hash": record.get("objective_hash"),
        "objective_summary": record.get("objective_summary"),
        "completion_reason": record.get("completion_reason"),
        "failure_reason": record.get("failure_reason"),
    }
    status = str(record.get("status", "success"))
    return builder.create(
        event_type=event_type,
        outcome=Outcome(status=status, code=str(record.get("code", status.upper()))),
        data={key: value for key, value in data.items() if value is not None},
    )


def agent_policy_pack_payload(decision: dict[str, Any]) -> dict[str, Any]:
    """Map an AgentPolicyPack-like decision dictionary to an audit policy payload."""

    return {
        "policy_engine": decision.get("policy_engine", "agentpolicypack"),
        "bundle_id": decision.get("bundle_id"),
        "bundle_version": decision.get("bundle_version"),
        "bundle_digest": decision.get("bundle_digest"),
        "decision_id": decision.get("decision_id"),
        "final_decision": decision.get("final_decision") or decision.get("decision"),
        "matched_policies": list(decision.get("matched_policies", [])),
        "controlling_policy": decision.get("controlling_policy"),
        "conflict_strategy": decision.get("conflict_strategy"),
        "obligations": list(decision.get("obligations", [])),
        "effective_limits": dict(decision.get("effective_limits", {})),
        "evidence_digest": decision.get("evidence_digest"),
        "reason": decision.get("reason"),
        "missing_context": list(decision.get("missing_context", [])),
        "warnings": list(decision.get("warnings", [])),
        "review_requirements": list(decision.get("review_requirements", [])),
    }


def model_swap_bench_context(result: dict[str, Any]) -> BenchmarkContext:
    """Map a ModelSwapBench-like result dictionary to benchmark context."""

    return BenchmarkContext(
        benchmark_id=result.get("benchmark_id"),
        benchmark_version=result.get("benchmark_version"),
        case_id=result.get("case_id"),
        run_id=result.get("run_id"),
        provider=result.get("provider"),
        model=result.get("model"),
        evaluator_results=dict(result.get("evaluator_results", {})),
        success=result.get("success"),
        cost_per_successful_outcome=result.get("cost_per_successful_outcome"),
        replacement_decision=result.get("replacement_decision"),
        cascade_decision=result.get("cascade_decision"),
    )


def open_ontology_lite_context(entity: dict[str, Any]) -> OntologyContext:
    """Map an OpenOntologyLite-like entity/action dictionary to ontology context."""

    return OntologyContext(
        ontology_id=entity.get("ontology_id"),
        ontology_version=entity.get("ontology_version"),
        ontology_digest=entity.get("ontology_digest"),
        entity_type=entity.get("entity_type"),
        entity_id=entity.get("entity_id"),
        action_name=entity.get("action_name"),
        relationship_context=dict(entity.get("relationship_context", {})),
        namespace=entity.get("namespace"),
    )


def private_ai_stack_metadata(record: dict[str, Any]) -> dict[str, Any]:
    """Map PrivateAIStack-like deployment metadata to event extension fields."""

    keys = (
        "deployment_id",
        "rag_pipeline_id",
        "governance_profile",
        "data_boundary",
        "local_only",
        "observability_run_id",
    )
    return {"privateaistack": {key: record[key] for key in keys if key in record}}
