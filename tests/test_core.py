from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ai_audit_log.builder import EventBuilder
from ai_audit_log.canonical import canonical_json_bytes
from ai_audit_log.chain import ChainVerifier, append_integrity
from ai_audit_log.cli import app
from ai_audit_log.digest import event_digest
from ai_audit_log.ids import new_event_id
from ai_audit_log.models import Actor, AuditEvent, Outcome, Source
from ai_audit_log.privacy import PrivacyMode, PrivacyProfile, redact_value
from ai_audit_log.query import filter_events
from ai_audit_log.storage import JsonlStore, SQLiteIndex
from ai_audit_log.time import now_utc

ROOT = Path(__file__).resolve().parents[1]
RUNNER = CliRunner()


def example_event() -> AuditEvent:
    return AuditEvent.model_validate_json((ROOT / "examples/basic/event.json").read_text())


def test_example_event_validates() -> None:
    event = example_event()
    assert event.event_type == "model.invocation.completed"
    assert event.outcome.status == "success"


def test_naive_datetime_rejected() -> None:
    data = json.loads((ROOT / "examples/basic/event.json").read_text())
    data["event_time"] = "2026-07-06T12:30:45"
    with pytest.raises(ValueError):
        AuditEvent.model_validate(data)


def test_custom_event_namespace_rules() -> None:
    data = json.loads((ROOT / "examples/basic/event.json").read_text())
    data["event_type"] = "example.organization.claim.reviewed"
    assert AuditEvent.model_validate(data).event_type == "example.organization.claim.reviewed"
    data["event_type"] = "model.organization.claim.reviewed"
    with pytest.raises(ValueError):
        AuditEvent.model_validate(data)


def test_event_ids_are_valid_and_unique() -> None:
    values = {new_event_id() for _ in range(1000)}
    assert len(values) == 1000


def test_canonicalization_is_stable_and_rejects_nan() -> None:
    assert canonical_json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    with pytest.raises(ValueError):
        canonical_json_bytes({"bad": float("nan")})


def test_digest_changes_when_event_changes() -> None:
    event = example_event()
    first = event_digest(event)
    event.outcome.reason = "Changed"
    assert event_digest(event) != first


def test_valid_chain_and_tamper_detection() -> None:
    first = append_integrity(example_event(), stream_id="s1", sequence=1, previous_event_digest=None)
    second = append_integrity(
        example_event().model_copy(update={"event_id": "0190f1a0-0000-4000-8000-000000000002"}),
        stream_id="s1",
        sequence=2,
        previous_event_digest=first.integrity.event_digest,
    )
    assert ChainVerifier().verify([first, second]).ok
    second.outcome.reason = "tampered"
    report = ChainVerifier().verify([first, second])
    assert not report.ok
    assert any(issue.code == "event_digest" for issue in report.issues)


def test_sequence_gap_duplicate_and_stream_mixing() -> None:
    first = append_integrity(example_event(), stream_id="s1", sequence=1, previous_event_digest=None)
    second = append_integrity(
        example_event().model_copy(update={"event_id": "0190f1a0-0000-4000-8000-000000000003"}),
        stream_id="s2",
        sequence=3,
        previous_event_digest=first.integrity.event_digest,
    )
    report = ChainVerifier().verify([first, second])
    assert not report.ok
    assert {"stream_mixing", "sequence_gap"} <= {issue.code for issue in report.issues}


def test_redaction_removes_secrets_and_content() -> None:
    value = {
        "Authorization": "Bearer secret",
        "nested": {"api_key": "abc", "prompt": "store me"},
        "items": [{"password": "pw"}],
    }
    redacted = redact_value(value, PrivacyProfile(mode=PrivacyMode.MINIMAL))
    dumped = json.dumps(redacted)
    assert "Bearer secret" not in dumped
    assert "abc" not in dumped
    assert "store me" not in dumped
    assert dumped.count("[REDACTED]") >= 3


def test_builder_privacy_defaults() -> None:
    builder = EventBuilder(
        source=Source(service="svc"),
        actor=Actor(actor_id="system", actor_type="system"),
    )
    event = builder.create(
        event_type="tool.call.completed",
        outcome=Outcome(status="success", code="OK"),
        data={"tool_name": "x", "api_key": "secret-value"},
    )
    assert event.data["api_key"] == "[REDACTED]"


def test_jsonl_store_and_query(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    event = append_integrity(example_event(), stream_id="s1", sequence=1, previous_event_digest=None)
    store = JsonlStore(path)
    store.append(event)
    loaded = store.read_all()
    assert loaded[0].event_id == event.event_id
    assert filter_events(loaded, event_type="model.invocation.completed")[0].event_id == event.event_id


def test_sqlite_index(tmp_path: Path) -> None:
    event = append_integrity(example_event(), stream_id="s1", sequence=1, previous_event_digest=None)
    index = SQLiteIndex(tmp_path / "audit.db")
    index.append(event)
    assert index.query(event_type="model.invocation.completed")[0].event_id == event.event_id


def test_cli_acceptance_path(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    event = ROOT / "examples/basic/event.json"
    checkpoint = tmp_path / "checkpoint.json"
    report = tmp_path / "report.md"
    redacted = tmp_path / "redacted.jsonl"
    schemas = tmp_path / "schemas"

    assert RUNNER.invoke(app, ["validate", str(event)]).exit_code == 0
    assert RUNNER.invoke(app, ["inspect", str(event)]).exit_code == 0
    assert RUNNER.invoke(app, ["append", str(log), "--event", str(event)]).exit_code == 0
    assert RUNNER.invoke(app, ["verify", str(log)]).exit_code == 0
    assert RUNNER.invoke(app, ["query", str(log), "--event-type", "model.invocation.completed"]).exit_code == 0
    assert RUNNER.invoke(app, ["summarize", str(log)]).exit_code == 0
    assert RUNNER.invoke(app, ["checkpoint", "create", str(log), "--output", str(checkpoint)]).exit_code == 0
    assert RUNNER.invoke(app, ["checkpoint", "verify", str(checkpoint), "--log", str(log)]).exit_code == 0
    assert RUNNER.invoke(app, ["export", str(log), "--format", "markdown", "--output", str(report)]).exit_code == 0
    assert RUNNER.invoke(
        app,
        [
            "redact",
            str(log),
            "--profile",
            str(ROOT / "examples/privacy/minimal.yaml"),
            "--output",
            str(redacted),
        ],
    ).exit_code == 0
    assert RUNNER.invoke(app, ["schema", "list"]).exit_code == 0
    assert RUNNER.invoke(app, ["schema", "export", "--output", str(schemas)]).exit_code == 0
    assert report.exists()
    assert (schemas / "audit-event-v1.schema.json").exists()


def test_cli_signatures(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "checkpoint.json"
    private = tmp_path / "development-private.pem"
    public = tmp_path / "development-public.pem"
    event = ROOT / "examples/basic/event.json"

    assert RUNNER.invoke(app, ["append", str(log), "--event", str(event)]).exit_code == 0
    assert RUNNER.invoke(app, ["checkpoint", "create", str(log), "--output", str(checkpoint)]).exit_code == 0
    assert (
        RUNNER.invoke(app, ["key", "generate", "--private-key", str(private), "--public-key", str(public)]).exit_code
        == 0
    )
    assert (
        RUNNER.invoke(app, ["key", "generate", "--private-key", str(private), "--public-key", str(public)]).exit_code
        == 1
    )
    assert (
        RUNNER.invoke(app, ["sign", str(checkpoint), "--private-key", str(private), "--key-id", "dev"]).exit_code
        == 0
    )
    assert RUNNER.invoke(app, ["signature", "verify", str(checkpoint), "--public-key", str(public)]).exit_code == 0


def test_generated_event_time_is_aware() -> None:
    assert now_utc().tzinfo is not None
