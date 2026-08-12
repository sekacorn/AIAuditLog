"""Privacy profiles, redaction, and secret-key handling."""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from ai_audit_log.bounds import (
    MAX_PROFILE_BYTES,
    MAX_PROFILE_DEPTH,
    MAX_PROFILE_ITEMS,
    MAX_PROFILE_STRING_CHARS,
    validate_bounded_structure,
)
from ai_audit_log.constants import SECRET_KEYS

DEFAULT_REPLACEMENT = "[REDACTED]"

_PROFILE_KEYS = {
    "mode",
    "replacement",
    "redact_fields",
    "redact_key_patterns",
    "hash_fields",
    "hash_salt",
    "mask_fields",
    "allow_full_content",
    "omit_fields",
    "classification_redact",
    "redact_classified_payloads",
    "safe_excerpt_chars",
}


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ValueError("privacy profile mapping keys must be strings")
        if key in result:
            raise ValueError(f"privacy profile contains duplicate key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


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

    def __post_init__(self) -> None:
        if not isinstance(self.mode, PrivacyMode):
            raise ValueError("mode must be a PrivacyMode")
        for name, value in (("replacement", self.replacement), ("hash_salt", self.hash_salt)):
            if not isinstance(value, str) or len(value) > MAX_PROFILE_STRING_CHARS:
                raise ValueError(f"{name} must be a bounded string")
        profile_fields: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("redact_fields", self.redact_fields),
            ("redact_key_patterns", self.redact_key_patterns),
            ("hash_fields", self.hash_fields),
            ("mask_fields", self.mask_fields),
            ("omit_fields", self.omit_fields),
            ("classification_redact", self.classification_redact),
        )
        for profile_name, profile_values in profile_fields:
            if not isinstance(profile_values, tuple) or len(profile_values) > MAX_PROFILE_ITEMS:
                raise ValueError(f"{profile_name} must be a bounded tuple")
            if any(not isinstance(item, str) or len(item) > MAX_PROFILE_STRING_CHARS for item in profile_values):
                raise ValueError(f"{profile_name} must contain bounded strings")
        if type(self.allow_full_content) is not bool or type(self.redact_classified_payloads) is not bool:
            raise ValueError("privacy profile flags must be booleans")
        if type(self.safe_excerpt_chars) is not int or not 0 <= self.safe_excerpt_chars <= MAX_PROFILE_STRING_CHARS:
            raise ValueError("safe_excerpt_chars is outside the supported range")

    @classmethod
    def from_file(cls, path: str) -> PrivacyProfile:
        """Load a YAML or JSON-like privacy profile."""

        raw = Path(path).read_bytes()
        if len(raw) > MAX_PROFILE_BYTES:
            raise ValueError("privacy profile exceeds maximum file size")
        if any(isinstance(event, AliasEvent) for event in yaml.parse(raw, Loader=yaml.SafeLoader)):
            raise ValueError("privacy profile YAML aliases are not supported")
        loader = _UniqueKeySafeLoader(raw)
        dispose = cast(Callable[[], None], loader.dispose)
        try:
            loaded = loader.get_single_data() or {}
        finally:
            dispose()
        if not isinstance(loaded, dict):
            raise ValueError("privacy profile root must be a mapping")
        validate_bounded_structure(
            loaded,
            label="privacy profile",
            max_depth=MAX_PROFILE_DEPTH,
            max_items=MAX_PROFILE_ITEMS,
            max_string_chars=MAX_PROFILE_STRING_CHARS,
        )
        unknown = sorted(set(loaded) - _PROFILE_KEYS)
        if unknown:
            raise ValueError(f"privacy profile contains unsupported fields: {', '.join(unknown)}")

        def strings(name: str, default: list[str]) -> tuple[str, ...]:
            value = loaded.get(name, default)
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError(f"{name} must be a list of strings")
            return tuple(value)

        def string(name: str, default: str) -> str:
            value = loaded.get(name, default)
            if not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
            return value

        def boolean(name: str, default: bool) -> bool:
            value = loaded.get(name, default)
            if type(value) is not bool:
                raise ValueError(f"{name} must be a boolean")
            return value

        safe_excerpt_chars = loaded.get("safe_excerpt_chars", 160)
        if type(safe_excerpt_chars) is not int:
            raise ValueError("safe_excerpt_chars must be an integer")
        return cls(
            mode=PrivacyMode(string("mode", PrivacyMode.MINIMAL.value)),
            replacement=string("replacement", DEFAULT_REPLACEMENT),
            redact_fields=strings("redact_fields", []),
            redact_key_patterns=strings("redact_key_patterns", sorted(SECRET_KEYS)),
            hash_fields=strings("hash_fields", []),
            hash_salt=string("hash_salt", ""),
            mask_fields=strings("mask_fields", []),
            allow_full_content=boolean("allow_full_content", False),
            omit_fields=strings("omit_fields", []),
            classification_redact=strings("classification_redact", ["restricted"]),
            redact_classified_payloads=boolean("redact_classified_payloads", True),
            safe_excerpt_chars=safe_excerpt_chars,
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
