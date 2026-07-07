from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ai_audit_log.builder import EventBuilder
from ai_audit_log.canonical import canonical_json_bytes
from ai_audit_log.checkpoint import Checkpoint, create_checkpoint
from ai_audit_log.checkpoint_policy import CheckpointSignaturePolicy, verify_checkpoint_policy
from ai_audit_log.cli import app
from ai_audit_log.compression import gunzip_file, gzip_file
from ai_audit_log.ecosystem import (
    agent_policy_pack_payload,
    forge_agent_step_event,
    model_swap_bench_context,
    open_ontology_lite_context,
    private_ai_stack_metadata,
)
from ai_audit_log.migration import migrate_event_document
from ai_audit_log.models import Actor, AuditEvent, Outcome, Source
from ai_audit_log.otel import correlation_from_traceparent, traceparent_from_correlation
from ai_audit_log.privacy import PrivacyMode, PrivacyProfile, redact_value
from ai_audit_log.recorder import AuditRecorder
from ai_audit_log.rotation import RotationPolicy
from ai_audit_log.signatures import Ed25519KeyPair, sign_payload
from ai_audit_log.storage import JsonlStore

ROOT = Path(__file__).resolve().parents[1]
RUNNER = CliRunner()


def example_event() -> AuditEvent:
    return AuditEvent.model_validate_json((ROOT / "examples/basic/event.json").read_text())


def test_rfc8785_sample_vector() -> None:
    sample = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": "\u20ac$\u000f\nA'B\"\\\\\"/",
        "literals": [None, True, False],
    }
    expected = (
        b'{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonical_json_bytes(sample) == expected


def test_checkpoint_signature_policy() -> None:
    store_event = example_event()
    from ai_audit_log.chain import append_integrity

    event = append_integrity(store_event, stream_id="s1", sequence=1, previous_event_digest=None)
    checkpoint = create_checkpoint([event])
    key_pair = Ed25519KeyPair.generate()
    checkpoint.signatures.append(sign_payload(checkpoint.unsigned_payload(), key_pair.private_key, key_id="k1"))
    result = verify_checkpoint_policy(
        checkpoint,
        public_keys={"k1": key_pair.public_key},
        policy=CheckpointSignaturePolicy(allowed_key_ids=("k1",), minimum_signatures=1),
    )
    assert result.ok
    assert result.accepted_signatures == 1


def test_checkpoint_signature_policy_rejects_wrong_key_id() -> None:
    checkpoint = Checkpoint(stream_id="s1", event_count=0, terminal_digest=None)
    result = verify_checkpoint_policy(
        checkpoint,
        public_keys={},
        policy=CheckpointSignaturePolicy(require_signature=True),
    )
    assert not result.ok


def test_checkpoint_rejects_invalid_chain() -> None:
    import pytest

    from ai_audit_log.exceptions import IntegrityError

    with pytest.raises(IntegrityError):
        create_checkpoint([example_event()])


def test_signature_rejects_fingerprint_mismatch() -> None:
    from ai_audit_log.exceptions import SignatureError
    from ai_audit_log.signatures import verify_payload_signature

    key_pair = Ed25519KeyPair.generate()
    other_key_pair = Ed25519KeyPair.generate()
    payload = {"checkpoint": "digest"}
    record = sign_payload(payload, key_pair.private_key, key_id="k1")
    import pytest

    with pytest.raises(SignatureError):
        verify_payload_signature(payload, record, other_key_pair.public_key)


def test_stream_rotation_and_locking(tmp_path: Path) -> None:
    builder = EventBuilder(source=Source(service="svc"), actor=Actor(actor_id="system", actor_type="system"))
    store = JsonlStore(tmp_path / "audit.jsonl", use_lock=True)
    recorder = AuditRecorder(
        builder=builder,
        store=store,
        rotation_policy=RotationPolicy(max_events=1),
    )
    recorder.record(event_type="system.started", outcome=Outcome(status="success", code="STARTED"))
    recorder.record(event_type="system.stopped", outcome=Outcome(status="success", code="STOPPED"))
    assert (tmp_path / "audit.jsonl.0001").exists()
    assert len(store.read_all()) == 1


def test_gzip_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "audit-report.md"
    source.write_text("report\n", encoding="utf-8")
    compressed = gzip_file(source)
    restored = gunzip_file(compressed, tmp_path / "restored.md")
    assert restored.read_text(encoding="utf-8") == "report\n"


def test_richer_privacy_profiles() -> None:
    value = {"data": {"classification": "restricted", "safe": "nope", "secret": "nope"}}
    redacted = redact_value(value, PrivacyProfile.balanced())
    assert redacted["data"]["classification"] == "restricted"
    assert redacted["data"]["safe"] == "[REDACTED]"

    full = redact_value({"prompt": "keep"}, PrivacyProfile.full_content())
    assert full["prompt"] == "keep"
    assert PrivacyProfile.minimal().mode is PrivacyMode.MINIMAL


def test_schema_migration() -> None:
    document = json.loads((ROOT / "examples/basic/legacy-event.json").read_text())
    result = migrate_event_document(document)
    assert result.changed
    assert result.document["schema_version"] == "1.0"
    assert "event_id" in result.document
    assert "data" in result.document


def test_traceparent_helpers() -> None:
    traceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    correlation = correlation_from_traceparent(traceparent)
    assert correlation.trace_id == "0123456789abcdef0123456789abcdef"
    assert traceparent_from_correlation(correlation) == traceparent


def test_ecosystem_dictionary_adapters() -> None:
    builder = EventBuilder(source=Source(service="svc"), actor=Actor(actor_id="agent", actor_type="ai_agent"))
    event = forge_agent_step_event({"agent_id": "a1", "status": "success", "step_number": 2}, builder=builder)
    assert event.event_type == "agent.step.completed"
    assert event.data["framework"] == "forge"

    policy = agent_policy_pack_payload({"decision": "allowed", "matched_policies": ["p1"]})
    assert policy["final_decision"] == "allowed"
    assert policy["matched_policies"] == ["p1"]

    benchmark = model_swap_bench_context({"benchmark_id": "b1", "success": True})
    assert benchmark.benchmark_id == "b1"

    ontology = open_ontology_lite_context({"entity_type": "claim", "entity_id": "c1"})
    assert ontology.entity_type == "claim"

    extension = private_ai_stack_metadata({"deployment_id": "d1", "local_only": True, "ignored": "x"})
    assert extension == {"privateaistack": {"deployment_id": "d1", "local_only": True}}


def test_cli_new_commands(tmp_path: Path) -> None:
    event = ROOT / "examples/basic/event.json"
    legacy = ROOT / "examples/basic/legacy-event.json"
    log = tmp_path / "audit.jsonl"
    report = tmp_path / "report.md"
    migrated = tmp_path / "migrated.json"

    assert RUNNER.invoke(app, ["append", str(log), "--event", str(event), "--lock"]).exit_code == 0
    export_result = RUNNER.invoke(
        app,
        ["export", str(log), "--format", "markdown", "--output", str(report), "--compress"],
    )
    assert export_result.exit_code == 0
    assert report.with_suffix(report.suffix + ".gz").exists()
    assert RUNNER.invoke(app, ["compress", str(report)]).exit_code == 0
    assert RUNNER.invoke(app, ["migrate", str(legacy), "--output", str(migrated)]).exit_code == 0
    assert RUNNER.invoke(app, ["rotate", str(log)]).exit_code == 0
    assert migrated.exists()
