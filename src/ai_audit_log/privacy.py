"""Privacy profiles, redaction, and secret-key handling."""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import yaml

from ai_audit_log.constants import SECRET_KEYS

DEFAULT_REPLACEMENT = "[REDACTED]"


class PrivacyMode(StrEnum):
    """Supported privacy modes."""

    MINIMAL = "minimal"
    BALANCED = "balanced"
    FULL_CONTENT = "full-content"


@dataclass(frozen=True)
class PrivacyProfile:
    """Configuration for deterministic redaction."""

    mode: PrivacyMode = PrivacyMode.MINIMAL
    replacement: str = DEFAULT_REPLACEMENT
    redact_fields: tuple[str, ...] = ()
    redact_key_patterns: tuple[str, ...] = tuple(sorted(SECRET_KEYS))
    hash_fields: tuple[str, ...] = ()
    hash_salt: str = ""
    mask_fields: tuple[str, ...] = ()
    allow_full_content: bool = False
    omit_fields: tuple[str, ...] = ()
    classification_redact: tuple[str, ...] = ("restricted",)
    redact_classified_payloads: bool = True
    safe_excerpt_chars: int = 160

    @classmethod
    def from_file(cls, path: str) -> PrivacyProfile:
        """Load a YAML or JSON-like privacy profile."""

        with open(path, encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        return cls(
            mode=PrivacyMode(loaded.get("mode", PrivacyMode.MINIMAL)),
            replacement=str(loaded.get("replacement", DEFAULT_REPLACEMENT)),
            redact_fields=tuple(loaded.get("redact_fields", [])),
            redact_key_patterns=tuple(loaded.get("redact_key_patterns", sorted(SECRET_KEYS))),
            hash_fields=tuple(loaded.get("hash_fields", [])),
            hash_salt=str(loaded.get("hash_salt", "")),
            mask_fields=tuple(loaded.get("mask_fields", [])),
            allow_full_content=bool(loaded.get("allow_full_content", False)),
            omit_fields=tuple(loaded.get("omit_fields", [])),
            classification_redact=tuple(loaded.get("classification_redact", ["restricted"])),
            redact_classified_payloads=bool(loaded.get("redact_classified_payloads", True)),
            safe_excerpt_chars=int(loaded.get("safe_excerpt_chars", 160)),
        )

    @classmethod
    def minimal(cls) -> PrivacyProfile:
        """Return the built-in minimal profile."""

        return cls(mode=PrivacyMode.MINIMAL)

    @classmethod
    def balanced(cls) -> PrivacyProfile:
        """Return the built-in balanced profile."""

        return cls(mode=PrivacyMode.BALANCED, redact_fields=("*.raw_*",), mask_fields=("*.subject_id",))

    @classmethod
    def full_content(cls) -> PrivacyProfile:
        """Return the explicit full-content profile."""

        return cls(mode=PrivacyMode.FULL_CONTENT, allow_full_content=True)


def _matches(path: str, key: str, patterns: tuple[str, ...]) -> bool:
    lowered_key = key.lower()
    lowered_path = path.lower()
    return any(
        fnmatch.fnmatch(lowered_key, pattern.lower()) or fnmatch.fnmatch(lowered_path, pattern.lower())
        for pattern in patterns
    )


def _mask(value: Any) -> str:
    text = str(value)
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * max(4, len(text) - 4)}{text[-2:]}"


def _hash(value: Any, salt: str) -> str:
    payload = f"{salt}:{value}".encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def redact_value(value: Any, profile: PrivacyProfile | None = None, path: str = "") -> Any:
    """Return a redacted copy of a JSON-like value without mutating the input."""

    active = profile or PrivacyProfile()
    if isinstance(value, dict):
        if _classified_payload_should_redact(value, active, path):
            return {key: item if key == "classification" else active.replacement for key, item in value.items()}
        result: dict[str, Any] = {}
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else key
            if _matches(child_path, key, active.omit_fields):
                continue
            if _matches(child_path, key, active.hash_fields):
                result[key] = _hash(item, active.hash_salt)
            elif _matches(child_path, key, active.mask_fields):
                result[key] = _mask(item)
            elif _matches(child_path, key, active.redact_fields + active.redact_key_patterns):
                result[key] = active.replacement
            elif key.lower() in {"prompt", "response", "content", "full_content"}:
                if active.mode is PrivacyMode.FULL_CONTENT and active.allow_full_content:
                    result[key] = item
                elif active.mode is PrivacyMode.BALANCED:
                    result[key] = str(item)[: active.safe_excerpt_chars]
                else:
                    result[key] = active.replacement
            elif key.lower() == "headers" and isinstance(item, dict):
                result[key] = redact_value(item, active, child_path)
            else:
                result[key] = redact_value(item, active, child_path)
        return result
    if isinstance(value, list):
        return [redact_value(item, active, f"{path}[]") for item in value]
    return value


def _classified_payload_should_redact(value: dict[str, Any], profile: PrivacyProfile, path: str) -> bool:
    classification = value.get("classification") or value.get("highest_classification")
    return (
        profile.redact_classified_payloads
        and path.lower().endswith("data")
        and isinstance(classification, str)
        and classification in profile.classification_redact
    )


def redaction_manifest(profile: PrivacyProfile) -> dict[str, Any]:
    """Return metadata describing a redaction run."""

    return {
        "mode": profile.mode.value,
        "replacement": profile.replacement,
        "redact_fields": list(profile.redact_fields),
        "redact_key_patterns": list(profile.redact_key_patterns),
        "hash_fields": list(profile.hash_fields),
        "mask_fields": list(profile.mask_fields),
        "classification_redact": list(profile.classification_redact),
        "redact_classified_payloads": profile.redact_classified_payloads,
        "full_content_enabled": profile.allow_full_content,
    }
