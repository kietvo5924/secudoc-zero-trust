"""Digital Signature Engine (RSA-PKCS#1 v1.5 with SHA-256).

Supports both raw hash signatures and Canonical Metadata-Bound Payloads
to prevent metadata tampering in storage/database layers.
"""
import json
import hashlib
from typing import Any
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def build_canonical_payload(
    doc_uuid: str,
    doc_hash: str,
    recipient_name: str,
    doc_type: str,
    issuer_name: str,
    issued_at: str,
    version: int = 1
) -> dict[str, Any]:
    """
    Construct a deterministic, canonical dictionary binding document content hash with essential metadata.
    Any alteration to recipient_name, doc_type, issuer_name, or timestamps will invalidate the signature.
    """
    return {
        "doc_hash": doc_hash.lower().strip(),
        "doc_type": doc_type.strip(),
        "doc_uuid": doc_uuid.strip(),
        "issued_at": issued_at.strip(),
        "issuer_name": issuer_name.strip(),
        "recipient_name": recipient_name.strip(),
        "version": version
    }


def serialize_canonical_payload(payload: dict[str, Any]) -> bytes:
    """Serialize canonical payload using sorted keys and compact separators to ensure deterministic byte representation."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_payload_digest(payload: dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of the serialized canonical payload."""
    return hashlib.sha256(serialize_canonical_payload(payload)).hexdigest()


def sign_hash(private_key: rsa.RSAPrivateKey, hash_hex: str) -> str:
    """
    Sign a SHA-256 hexadecimal hash string using the RSA private key.
    Returns: Signature encoded as a hexadecimal string.
    """
    message_bytes = hash_hex.encode("utf-8")
    signature = private_key.sign(
        message_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()


def sign_canonical_payload(private_key: rsa.RSAPrivateKey, payload: dict[str, Any]) -> str:
    """Sign the SHA-256 digest of a canonical metadata-bound payload."""
    digest = compute_payload_digest(payload)
    return sign_hash(private_key, digest)


def verify_signature(public_key: rsa.RSAPublicKey, hash_hex: str, signature_hex: str) -> bool:
    """
    Verify whether a hexadecimal RSA signature matches the given hash string.
    Returns: True if valid; False if forged, corrupted, or signed by another key.
    """
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        message_bytes = hash_hex.encode("utf-8")
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_canonical_signature(public_key: rsa.RSAPublicKey, payload: dict[str, Any], signature_hex: str) -> bool:
    """Verify whether a signature matches the SHA-256 digest of the given canonical metadata payload."""
    digest = compute_payload_digest(payload)
    return verify_signature(public_key, digest, signature_hex)

