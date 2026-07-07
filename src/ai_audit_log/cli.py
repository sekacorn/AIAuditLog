"""Command-line interface for AIAuditLog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from ai_audit_log import __version__
from ai_audit_log.chain import ChainVerifier, append_integrity
from ai_audit_log.checkpoint import Checkpoint, create_checkpoint, verify_checkpoint
from ai_audit_log.compression import gzip_file
from ai_audit_log.exports import export_events
from ai_audit_log.migration import migrate_event_document
from ai_audit_log.models import AuditEvent
from ai_audit_log.privacy import PrivacyProfile, redact_value
from ai_audit_log.query import filter_events
from ai_audit_log.reports import inspect_event, markdown_report, summarize_events
from ai_audit_log.rotation import RotationPolicy, rotate_stream
from ai_audit_log.schema import export_schemas, schema_names
from ai_audit_log.signatures import (
    Ed25519KeyPair,
    load_private_key,
    load_public_key,
    sign_payload,
    verify_payload_signature,
)
from ai_audit_log.storage import JsonlStore

app = typer.Typer(no_args_is_help=True)
checkpoint_app = typer.Typer(no_args_is_help=True)
schema_app = typer.Typer(no_args_is_help=True)
key_app = typer.Typer(no_args_is_help=True)
signature_app = typer.Typer(no_args_is_help=True)
app.add_typer(checkpoint_app, name="checkpoint")
app.add_typer(schema_app, name="schema")
app.add_typer(key_app, name="key")
app.add_typer(signature_app, name="signature")


def _echo_json(value: object) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True, default=str))


def _read_event(path: Path) -> AuditEvent:
    return AuditEvent.model_validate_json(path.read_text(encoding="utf-8"))


def _read_log(path: Path) -> list[AuditEvent]:
    return JsonlStore(path).read_all()


def version_callback(value: bool) -> None:
    """Print version and exit."""

    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Portable, privacy-aware, tamper-evident audit logs for AI systems."""


@app.command()
def validate(event: Annotated[Path, typer.Argument(help="Event JSON file.")]) -> None:
    """Validate an event JSON file."""

    _read_event(event)
    typer.echo("valid")


@app.command()
def inspect(event: Annotated[Path, typer.Argument(help="Event JSON file.")]) -> None:
    """Inspect an event JSON file."""

    _echo_json(inspect_event(_read_event(event)))


@app.command()
def append(
    log: Annotated[Path, typer.Argument(help="JSONL log path.")],
    event: Annotated[Path, typer.Option("--event", help="Event JSON file.")],
    stream_id: Annotated[str, typer.Option("--stream-id")] = "default",
    lock: Annotated[bool, typer.Option("--lock", help="Use lock-file guarded append.")] = False,
) -> None:
    """Append an event to a JSONL stream with hash-chain metadata."""

    store = JsonlStore(log, use_lock=lock)
    if lock:
        chained = store.append_chained(_read_event(event), stream_id=stream_id)
        _echo_json({"appended": chained.event_id, "sequence": chained.integrity.sequence})
        return
    existing = store.read_all()
    previous = existing[-1].integrity.event_digest if existing else None
    chained = append_integrity(
        _read_event(event),
        stream_id=stream_id,
        sequence=len(existing) + 1,
        previous_event_digest=previous,
    )
    store.append(chained)
    _echo_json({"appended": chained.event_id, "sequence": chained.integrity.sequence})


@app.command()
def verify(log: Annotated[Path, typer.Argument(help="JSONL log path.")]) -> None:
    """Verify a JSONL hash chain."""

    report = ChainVerifier().verify(_read_log(log))
    _echo_json(
        {
            "ok": report.ok,
            "event_count": report.event_count,
            "stream_id": report.stream_id,
            "terminal_digest": report.terminal_digest,
            "issues": [issue.__dict__ for issue in report.issues],
        }
    )
    if not report.ok:
        raise typer.Exit(1)


@app.command()
def query(
    log: Annotated[Path, typer.Argument(help="JSONL log path.")],
    event_type: Annotated[str | None, typer.Option("--event-type")] = None,
    status: Annotated[str | None, typer.Option("--status")] = None,
    stream_id: Annotated[str | None, typer.Option("--stream-id")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 100,
) -> None:
    """Filter a JSONL stream."""

    events = filter_events(
        _read_log(log),
        event_type=event_type,
        status=status,
        stream_id=stream_id,
        limit=limit,
    )
    _echo_json([event.model_dump(mode="json", exclude_none=True) for event in events])


@app.command()
def summarize(log: Annotated[Path, typer.Argument(help="JSONL log path.")]) -> None:
    """Summarize a JSONL stream."""

    _echo_json(summarize_events(_read_log(log)))


@checkpoint_app.command("create")
def checkpoint_create(
    log: Annotated[Path, typer.Argument(help="JSONL log path.")],
    output: Annotated[Path, typer.Option("--output", help="Checkpoint JSON path.")],
) -> None:
    """Create a stream checkpoint."""

    checkpoint = create_checkpoint(_read_log(log))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(checkpoint.model_dump_json(indent=2, exclude_none=True) + "\n", encoding="utf-8")
    _echo_json({"checkpoint": str(output), "digest": checkpoint.checkpoint_digest})


@checkpoint_app.command("verify")
def checkpoint_verify(
    checkpoint: Annotated[Path, typer.Argument(help="Checkpoint JSON path.")],
    log: Annotated[Path, typer.Option("--log", help="JSONL log path.")],
) -> None:
    """Verify a checkpoint against a log."""

    loaded = Checkpoint.model_validate_json(checkpoint.read_text(encoding="utf-8"))
    result = verify_checkpoint(loaded, _read_log(log))
    _echo_json({"ok": result.ok, "issues": result.issues})
    if not result.ok:
        raise typer.Exit(1)


@app.command()
def export(
    log: Annotated[Path, typer.Argument(help="JSONL log path.")],
    fmt: Annotated[str, typer.Option("--format", help="jsonl, json, csv, markdown")] = "jsonl",
    output: Annotated[Path, typer.Option("--output", help="Output path.")] = Path("audit-export.jsonl"),
    compress: Annotated[bool, typer.Option("--compress", help="Also write deterministic gzip output.")] = False,
) -> None:
    """Export a JSONL stream."""

    export_events(_read_log(log), fmt=fmt, output=output, compress=compress)
    payload = {"output": str(output), "format": fmt}
    if compress:
        payload["compressed_output"] = str(output.with_suffix(output.suffix + ".gz"))
    _echo_json(payload)


@app.command()
def compress(
    path: Annotated[Path, typer.Argument(help="File to gzip.")],
    output: Annotated[Path | None, typer.Option("--output", help="Compressed output path.")] = None,
) -> None:
    """Create a deterministic gzip copy of a file."""

    compressed = gzip_file(path, output)
    _echo_json({"output": str(compressed)})


@app.command()
def rotate(
    log: Annotated[Path, typer.Argument(help="JSONL log path.")],
    suffix_width: Annotated[int, typer.Option("--suffix-width")] = 4,
) -> None:
    """Rotate a JSONL stream to the next numbered path."""

    rotated = rotate_stream(log, RotationPolicy(suffix_width=suffix_width))
    _echo_json({"rotated": str(rotated)})


@app.command()
def migrate(
    event: Annotated[Path, typer.Argument(help="Event JSON file.")],
    output: Annotated[Path, typer.Option("--output", help="Migrated output path.")],
) -> None:
    """Migrate an early alpha event document to the current schema version."""

    document = json.loads(event.read_text(encoding="utf-8"))
    result = migrate_event_document(document)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _echo_json({"changed": result.changed, "warnings": result.warnings, "output": str(output)})


@app.command()
def redact(
    log: Annotated[Path, typer.Argument(help="JSONL log path.")],
    profile: Annotated[Path, typer.Option("--profile", help="Privacy YAML profile.")],
    output: Annotated[Path, typer.Option("--output", help="Output JSONL path.")],
) -> None:
    """Create a redacted JSONL export."""

    privacy = PrivacyProfile.from_file(str(profile))
    events = _read_log(log)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            doc = redact_value(event.model_dump(mode="json", exclude_none=True), privacy)
            handle.write(json.dumps(doc, sort_keys=True))
            handle.write("\n")
    _echo_json({"output": str(output), "events": len(events), "mode": privacy.mode.value})


@schema_app.command("list")
def schema_list() -> None:
    """List available schemas."""

    _echo_json(schema_names())


@schema_app.command("export")
def schema_export(output: Annotated[Path, typer.Option("--output", help="Schema output directory.")]) -> None:
    """Export JSON Schemas."""

    export_schemas(output)
    _echo_json({"output": str(output), "schemas": schema_names()})


@key_app.command("generate")
def key_generate(
    private_key: Annotated[Path, typer.Option("--private-key", help="Private key PEM path.")],
    public_key: Annotated[Path, typer.Option("--public-key", help="Public key PEM path.")],
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing key files.")] = False,
) -> None:
    """Generate an Ed25519 development key pair."""

    private_key.parent.mkdir(parents=True, exist_ok=True)
    public_key.parent.mkdir(parents=True, exist_ok=True)
    if not force and (private_key.exists() or public_key.exists()):
        _echo_json({"ok": False, "error": "key file already exists; use --force to overwrite"})
        raise typer.Exit(1)
    key_pair = Ed25519KeyPair.generate()
    key_pair.write_private_pem(private_key, overwrite=force)
    key_pair.write_public_pem(public_key)
    _echo_json({"public_key_fingerprint": key_pair.fingerprint})


@app.command()
def sign(
    checkpoint: Annotated[Path, typer.Argument(help="Checkpoint JSON path.")],
    private_key: Annotated[Path, typer.Option("--private-key", help="Private key PEM path.")],
    key_id: Annotated[str, typer.Option("--key-id", help="Key identifier.")],
) -> None:
    """Sign a checkpoint in place."""

    loaded = Checkpoint.model_validate_json(checkpoint.read_text(encoding="utf-8"))
    signature = sign_payload(loaded.unsigned_payload(), load_private_key(private_key), key_id=key_id)
    loaded.signatures.append(signature)
    checkpoint.write_text(loaded.model_dump_json(indent=2, exclude_none=True) + "\n", encoding="utf-8")
    _echo_json({"signed": str(checkpoint), "key_id": key_id})


@signature_app.command("verify")
def signature_verify(
    checkpoint: Annotated[Path, typer.Argument(help="Checkpoint JSON path.")],
    public_key: Annotated[Path, typer.Option("--public-key", help="Public key PEM path.")],
) -> None:
    """Verify checkpoint signatures."""

    loaded = Checkpoint.model_validate_json(checkpoint.read_text(encoding="utf-8"))
    if not loaded.signatures:
        _echo_json({"ok": False, "issues": ["checkpoint has no signatures"]})
        raise typer.Exit(1)
    public = load_public_key(public_key)
    for signature in loaded.signatures:
        verify_payload_signature(loaded.unsigned_payload(), signature, public)
    _echo_json({"ok": True, "signature_count": len(loaded.signatures)})


@app.command()
def report(
    log: Annotated[Path, typer.Argument(help="JSONL log path.")],
    output: Annotated[Path, typer.Option("--output", help="Markdown report path.")],
) -> None:
    """Write a Markdown report."""

    events = _read_log(log)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown_report(events, ChainVerifier().verify(events)), encoding="utf-8")
    _echo_json({"output": str(output)})


if __name__ == "__main__":
    app()
