"""Cryptographic Hashing Engine (SHA-256) for Document Integrity."""
import hashlib
from typing import BinaryIO
from pathlib import Path
from ..config import CHUNK_SIZE_BYTES


def calculate_bytes_hash(data: bytes) -> str:
    """Calculate the SHA-256 hexadecimal digest of raw bytes."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_file_hash(file_path: str | Path) -> str:
    """
    Calculate the SHA-256 hexadecimal digest of a file using chunked streaming.
    Prevents memory exhaustion on large files.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE_BYTES)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def calculate_stream_hash(stream: BinaryIO) -> str:
    """
    Calculate SHA-256 hash from an open file-like binary stream.
    Preserves the stream position if seekable.
    """
    hasher = hashlib.sha256()
    start_pos = 0
    if hasattr(stream, "seekable") and stream.seekable():
        try:
            start_pos = stream.tell()
        except (AttributeError, OSError):
            start_pos = 0

    while True:
        chunk = stream.read(CHUNK_SIZE_BYTES)
        if not chunk:
            break
        hasher.update(chunk)

    if hasattr(stream, "seekable") and stream.seekable():
        try:
            stream.seek(start_pos)
        except (AttributeError, OSError):
            pass

    return hasher.hexdigest()


def count_bit_differences(hex_hash1: str, hex_hash2: str) -> tuple[int, int, float]:
    """
    Calculate Hamming distance between two hex hashes to demonstrate Avalanche Effect.
    Returns: (different_bits, total_bits, percentage_difference)
    """
    bytes1 = bytes.fromhex(hex_hash1)
    bytes2 = bytes.fromhex(hex_hash2)
    min_len = min(len(bytes1), len(bytes2))
    
    diff_bits = 0
    total_bits = min_len * 8
    
    for i in range(min_len):
        xor_byte = bytes1[i] ^ bytes2[i]
        diff_bits += bin(xor_byte).count("1")
        
    percentage = (diff_bits / total_bits) * 100.0 if total_bits > 0 else 0.0
    return diff_bits, total_bits, percentage


def get_bit_difference_vector(hex_hash1: str, hex_hash2: str) -> list[int]:
    """
    Generate an array of 256 binary values (0: same, 1: flipped) between two SHA-256 hashes.
    Powers the interactive Avalanche Effect Heatmap in the presentation UI.
    """
    bytes1 = bytes.fromhex(hex_hash1)
    bytes2 = bytes.fromhex(hex_hash2)
    min_len = min(len(bytes1), len(bytes2))
    bit_vector: list[int] = []

    for i in range(min_len):
        xor_byte = bytes1[i] ^ bytes2[i]
        for b in range(7, -1, -1):
            bit_vector.append((xor_byte >> b) & 1)

    return bit_vector
