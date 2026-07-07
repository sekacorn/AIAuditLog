"""Ed25519 checkpoint signatures using cryptography."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ai_audit_log.canonical import canonical_json_bytes
from ai_audit_log.constants import SIGNATURE_ALGORITHM
from ai_audit_log.exceptions import SignatureError


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return a stable SHA-256 fingerprint for an Ed25519 public key."""

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    return f"sha256:{digest.finalize().hex()}"


@dataclass(frozen=True)
class Ed25519KeyPair:
    """Generated Ed25519 key pair."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> Ed25519KeyPair:
        """Generate a new Ed25519 key pair."""

        private = Ed25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())

    @property
    def fingerprint(self) -> str:
        """Stable public-key fingerprint."""

        return public_key_fingerprint(self.public_key)

    def write_private_pem(self, path: str | Path, *, overwrite: bool = False) -> None:
        """Write an unencrypted development private key without accidental overwrite."""

        private_path = Path(path)
        flags = os.O_WRONLY | os.O_CREAT
        if not overwrite:
            flags |= os.O_EXCL
        payload = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        handle = os.open(str(private_path), flags, 0o600)
        try:
            os.write(handle, payload)
        finally:
            os.close(handle)
        os.chmod(private_path, 0o600)

    def write_public_pem(self, path: str | Path) -> None:
        """Write a public key."""

        Path(path).write_bytes(
            self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM."""

    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("private key is not Ed25519")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM."""

    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError("public key is not Ed25519")
    return key


def sign_payload(payload: dict[str, Any], private_key: Ed25519PrivateKey, *, key_id: str) -> dict[str, Any]:
    """Sign canonical payload bytes."""

    signature = private_key.sign(canonical_json_bytes(payload))
    public = private_key.public_key()
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint(public),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_payload_signature(
    payload: dict[str, Any],
    signature_record: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> bool:
    """Verify an Ed25519 signature over canonical payload bytes."""

    if signature_record.get("algorithm") != SIGNATURE_ALGORITHM:
        raise SignatureError("unsupported signature algorithm")
    expected_fingerprint = signature_record.get("public_key_fingerprint")
    actual_fingerprint = public_key_fingerprint(public_key)
    if expected_fingerprint is not None and expected_fingerprint != actual_fingerprint:
        raise SignatureError("signature fingerprint does not match public key")
    try:
        public_key.verify(
            base64.b64decode(str(signature_record["signature"])),
            canonical_json_bytes(payload),
        )
    except (InvalidSignature, KeyError, ValueError) as exc:
        raise SignatureError("signature verification failed") from exc
    return True
