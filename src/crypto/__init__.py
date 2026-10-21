"""Cryptographic primitives and key management for SecuDoc."""
from .hashing import calculate_bytes_hash, calculate_file_hash, calculate_stream_hash, count_bit_differences
from .keys import KeyManager
from .signature import sign_hash, verify_signature
from .merkle import calculate_block_hash, verify_audit_chain

__all__ = [
    "calculate_bytes_hash",
    "calculate_file_hash",
    "calculate_stream_hash",
    "count_bit_differences",
    "KeyManager",
    "sign_hash",
    "verify_signature",
    "calculate_block_hash",
    "verify_audit_chain",
]
