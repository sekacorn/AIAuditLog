# Getting Started

Install locally:

```powershell
python -m pip install -e ".[dev]"
```

Quality commands:

```powershell
python -m ruff check .
python -m mypy --strict src
python -m pytest
python -m pytest --cov=ai_audit_log --cov-branch
python -m bandit -r src
python -m pip_audit
python -m build
python -m twine check dist/*
```

Acceptance commands:

```powershell
aiaudit validate examples/basic/event.json
aiaudit inspect examples/basic/event.json
aiaudit append build/audit.jsonl --event examples/basic/event.json
aiaudit verify build/audit.jsonl
aiaudit query build/audit.jsonl --event-type model.invocation.completed
aiaudit summarize build/audit.jsonl
aiaudit checkpoint create build/audit.jsonl --output build/checkpoint.json
aiaudit checkpoint verify build/checkpoint.json --log build/audit.jsonl
aiaudit export build/audit.jsonl --format markdown --output build/audit-report.md
aiaudit redact build/audit.jsonl --profile examples/privacy/minimal.yaml --output build/audit-redacted.jsonl
aiaudit schema list
aiaudit schema export --output build/schemas
```

Exit code `0` means the requested operation succeeded. Verification commands
return non-zero when integrity checks fail.
