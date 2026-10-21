"""Cryptographic primitives, signature engine, hash-chain ledger, and verifiable QR for SecuDoc."""
from .hashing import calculate_bytes_hash, calculate_file_hash, calculate_stream_hash, count_bit_differences, get_bit_difference_vector
from .keys import KeyManager
from .signature import sign_hash, verify_signature, build_canonical_payload, sign_canonical_payload, verify_canonical_signature
from .merkle import calculate_block_hash, verify_audit_chain, GENESIS_PREV_HASH
from .qr import generate_qr_data_uri, generate_qr_svg

__all__ = [
    "calculate_bytes_hash",
    "calculate_file_hash",
    "calculate_stream_hash",
    "count_bit_differences",
    "get_bit_difference_vector",
    "KeyManager",
    "sign_hash",
    "verify_signature",
    "build_canonical_payload",
    "sign_canonical_payload",
    "verify_canonical_signature",
    "calculate_block_hash",
    "verify_audit_chain",
    "GENESIS_PREV_HASH",
    "generate_qr_data_uri",
    "generate_qr_svg",
]

