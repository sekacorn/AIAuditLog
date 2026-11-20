"""Regression tests for Beta-blocking integrity and input-boundary fixes."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import ValidationError

from ai_audit_log.bounds import MAX_PROFILE_BYTES
from ai_audit_log.builder import EventBuilder
from ai_audit_log.chain import ChainVerifier, append_integrity
from ai_audit_log.checkpoint import Checkpoint, create_checkpoint, verify_checkpoint, verify_signed_checkpoint
from ai_audit_log.digest import sha256_digest
from ai_audit_log.exceptions import SignatureError
from ai_audit_log.models import Actor, AuditEvent, Outcome, Source
from ai_audit_log.privacy import PrivacyProfile, redact_value
from ai_audit_log.recorder import AuditRecorder
from ai_audit_log.rotation import RotationPolicy
from ai_audit_log.signatures import Ed25519KeyPair, sign_payload, verify_payload_signature
from ai_audit_log.storage import JsonlStore


def test_oversized_profile_uses_bounded_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "large.yaml"
    path.write_bytes(b"#" * (MAX_PROFILE_BYTES * 2))
    with path.open("rb") as stream:

        class Reader:
            def __enter__(self) -> Reader:
                return self

            def __exit__(self, *args: object) -> None:
                pass

            def read(self, size: int) -> bytes:
                assert size == MAX_PROFILE_BYTES + 1
                return stream.read(size)

        monkeypatch.setattr(Path, "open", lambda *args, **kwargs: Reader())
        with pytest.raises(ValueError, match="maximum file size"):
            PrivacyProfile.from_file(str(path))


def make_event(index: int = 0) -> AuditEvent:
    return AuditEvent(
        event_id=f"0190f1a0-0000-4000-8000-{index:012d}",
        event_type="system.started",
        event_time="2026-08-10T12:00:00Z",
        recorded_time="2026-08-10T12:00:00Z",
        source=Source(service="test"),
        actor=Actor(actor_id="system", actor_type="system"),
        outcome=Outcome(status="success", code="OK"),
    )


def make_recorder(path: Path, *, rotation_policy: RotationPolicy | None = None) -> AuditRecorder:
    return AuditRecorder(
        builder=EventBuilder(source=Source(service="test"), actor=Actor(actor_id="system", actor_type="system")),
        store=JsonlStore(path),
        rotation_policy=rotation_policy,
    )


def test_recorder_serializes_concurrent_cooperating_writers(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer_count = 12
    barrier = Barrier(writer_count)

    def record(index: int) -> int:
        barrier.wait()
        event = make_recorder(path).append_event(make_event(index + 1))
        assert event.integrity.sequence is not None
        return event.integrity.sequence

    with ThreadPoolExecutor(max_workers=writer_count) as pool:
        sequences = list(pool.map(record, range(writer_count)))

    events = JsonlStore(path).read_all()
    assert sorted(sequences) == list(range(1, writer_count + 1))
    assert [event.integrity.sequence for event in events] == list(range(1, writer_count + 1))
    assert ChainVerifier().verify(events).ok


def test_automatic_rotation_restarts_an_independent_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recorder = make_recorder(path, rotation_policy=RotationPolicy(max_events=1))
    for index in range(3):
        recorder.append_event(make_event(index + 1))

    paths = [path.with_name("audit.jsonl.0001"), path.with_name("audit.jsonl.0002"), path]
    for stream_path in paths:
        events = JsonlStore(stream_path).read_all()
        assert len(events) == 1
        assert events[0].integrity.sequence == 1
        assert events[0].integrity.previous_event_digest is None
        assert ChainVerifier().verify(events).ok


def test_chain_rejects_unsupported_declared_algorithms() -> None:
    event = append_integrity(make_event(), stream_id="s1", sequence=1, previous_event_digest=None)
    event.integrity.digest_algorithm = "sha1"
    event.integrity.chain_algorithm = "other"
    report = ChainVerifier().verify([event])
    assert not report.ok
    assert {issue.code for issue in report.issues} >= {"digest_algorithm", "chain_algorithm"}


def test_checkpoint_requires_strict_supported_metadata() -> None:
    with pytest.raises(ValidationError):
        Checkpoint.model_validate(
            {
                "stream_id": "s1",
                "event_count": 0,
                "terminal_digest": None,
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError):
        Checkpoint(stream_id="s1", event_count=1, terminal_digest="sha256:" + "0" * 64, chain_algorithm="other")
    with pytest.raises(ValidationError):
        Checkpoint(stream_id="s1", event_count=1, terminal_digest="not-a-digest")
    with pytest.raises(ValidationError):
        Checkpoint.model_validate({"stream_id": "s1", "event_count": "1", "terminal_digest": "sha256:" + "0" * 64})


def test_signed_checkpoint_requires_valid_stream_before_signature_policy() -> None:
    event = append_integrity(make_event(), stream_id="s1", sequence=1, previous_event_digest=None)
    checkpoint = create_checkpoint([event])
    key_pair = Ed25519KeyPair.generate()
    checkpoint.signatures.append(sign_payload(checkpoint.unsigned_payload(), key_pair.private_key, key_id="test"))
    assert verify_signed_checkpoint(checkpoint, [event], public_keys={"test": key_pair.public_key}).ok

    checkpoint.event_count = 2
    result = verify_signed_checkpoint(checkpoint, [event], public_keys={"test": key_pair.public_key})
    assert not result.ok
    assert result.signatures is None
    assert "checkpoint digest mismatch" in result.checkpoint.issues


def test_checkpoint_digest_validation_remains_compatible_for_older_payload_shape() -> None:
    old_checkpoint = Checkpoint(stream_id="s1", event_count=0, terminal_digest=None)
    old_checkpoint.checkpoint_digest = sha256_digest(old_checkpoint.unsigned_payload())
    assert verify_checkpoint(old_checkpoint, []).ok


def test_signature_parser_rejects_invalid_base64() -> None:
    key_pair = Ed25519KeyPair.generate()
    record = sign_payload({"value": "ok"}, key_pair.private_key, key_id="test")
    record["signature"] = "%%%"
    with pytest.raises(SignatureError):
        verify_payload_signature({"value": "ok"}, record, key_pair.public_key)


def test_event_bounds_reject_overlong_and_deep_payloads() -> None:
    event = make_event()
    with pytest.raises(ValidationError):
        event.data = {"text": "x" * 1_000_001}

    nested: dict[str, object] = {}
    for _ in range(65):
        nested = {"nested": nested}
    event = make_event()
    with pytest.raises(ValidationError):
        event.data = nested


def test_privacy_profile_loader_rejects_unsafe_or_ambiguous_input(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("mode: minimal\nmode: balanced\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        PrivacyProfile.from_file(str(duplicate))

    alias = tmp_path / "alias.yaml"
    alias.write_text("redact_fields: &patterns [token]\nhash_fields: *patterns\n", encoding="utf-8")
    with pytest.raises(ValueError, match="aliases"):
        PrivacyProfile.from_file(str(alias))

    unknown = tmp_path / "unknown.yaml"
    unknown.write_text("unexpected: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        PrivacyProfile.from_file(str(unknown))


def test_privacy_redaction_handles_common_secret_fields_without_mutating_input() -> None:
    source = {
        "authorization": "Bearer value",
        "api_key": "key-value",
        "private_key": "-----BEGIN PRIVATE KEY-----\nvalue",
        "nested": {"password": "password-value"},
        "prompt": "customer question",
    }
    redacted = redact_value(source)
    assert source["authorization"] == "Bearer value"
    assert "value" not in str(redacted)
    assert redacted["prompt"] == "[REDACTED]"
