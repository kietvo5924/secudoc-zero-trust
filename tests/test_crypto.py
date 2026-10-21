"""Unit Tests for Core Cryptographic Primitives (SHA-256, RSA-2048, Merkle Ledger)."""
import unittest
import tempfile
import os
from pathlib import Path
from src.crypto.hashing import calculate_bytes_hash, calculate_file_hash, count_bit_differences
from src.crypto.keys import KeyManager
from src.crypto.signature import sign_hash, verify_signature
from src.crypto.merkle import calculate_block_hash, verify_audit_chain, GENESIS_PREV_HASH
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class TestCryptoPrimitives(unittest.TestCase):
    """Test suite for cryptographic integrity, signatures, and hash chains."""

    def test_sha256_hash_correctness(self):
        """TC-CRYPTO-01: Verify SHA-256 calculation matches known standard digests."""
        empty_hash = calculate_bytes_hash(b"")
        self.assertEqual(empty_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        hello_hash = calculate_bytes_hash(b"hello world")
        self.assertEqual(hello_hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    def test_sha256_avalanche_effect(self):
        """TC-CRYPTO-02: Verify Avalanche Effect: flipping 1 bit changes > 40% of output bits."""
        msg1 = b"Official University Transcript: Grade A"
        msg2 = bytearray(msg1)
        msg2[0] ^= 0x01 # Flip lowest bit of first char

        hash1 = calculate_bytes_hash(msg1)
        hash2 = calculate_bytes_hash(bytes(msg2))

        diff_bits, total_bits, pct = count_bit_differences(hash1, hash2)
        self.assertGreater(pct, 40.0, f"Avalanche effect too weak: {pct}%")
        self.assertEqual(total_bits, 256)

    def test_rsa_key_generation_and_loading(self):
        """TC-CRYPTO-03: Verify RSA KeyManager generates valid 2048-bit keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path = Path(tmpdir) / "test_priv.pem"
            pub_path = Path(tmpdir) / "test_pub.pem"
            km = KeyManager(priv_path, pub_path, key_size=2048)

            self.assertTrue(priv_path.exists())
            self.assertTrue(pub_path.exists())

            priv_key = km.get_private_key()
            pub_key = km.get_public_key()
            self.assertEqual(priv_key.key_size, 2048)
            self.assertEqual(pub_key.key_size, 2048)

            # Test reload from disk
            km2 = KeyManager(priv_path, pub_path, key_size=2048)
            self.assertEqual(km2.get_public_key_pem(), km.get_public_key_pem())

    def test_signature_validity(self):
        """TC-CRYPTO-04: Sign a SHA-256 digest and verify it succeeds with matching public key."""
        km = KeyManager()
        priv_key = km.get_private_key()
        pub_key = km.get_public_key()

        sample_hash = calculate_bytes_hash(b"Secure Document Content 2026")
        signature_hex = sign_hash(priv_key, sample_hash)

        self.assertIsInstance(signature_hex, str)
        self.assertEqual(len(signature_hex), 512) # 2048 bits = 256 bytes = 512 hex chars

        # Verify should return True
        self.assertTrue(verify_signature(pub_key, sample_hash, signature_hex))

    def test_signature_rejection_on_altered_hash(self):
        """TC-CRYPTO-05: Signature verification must FAIL if the hash was altered by even 1 character."""
        km = KeyManager()
        priv_key = km.get_private_key()
        pub_key = km.get_public_key()

        sample_hash = calculate_bytes_hash(b"Original Contract")
        signature_hex = sign_hash(priv_key, sample_hash)

        # Alter hash
        altered_hash = sample_hash[:-1] + ("0" if sample_hash[-1] != "0" else "1")
        self.assertFalse(verify_signature(pub_key, altered_hash, signature_hex))

    def test_signature_rejection_with_rogue_key(self):
        """TC-CRYPTO-06: Signature verified against a different public key must FAIL."""
        km = KeyManager()
        priv_key = km.get_private_key()

        rogue_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        ).public_key()

        sample_hash = calculate_bytes_hash(b"Legitimate Certificate")
        signature_hex = sign_hash(priv_key, sample_hash)

        self.assertFalse(verify_signature(rogue_key, sample_hash, signature_hex))

    def test_audit_chain_calculation_and_verification(self):
        """TC-CRYPTO-07: Verify integrity of a 3-block cryptographic hash chain."""
        b0_hash = calculate_block_hash(0, GENESIS_PREV_HASH, "2026-01-01T00:00:00Z", "GENESIS", "uuid-0", "payload-0")
        b1_hash = calculate_block_hash(1, b0_hash, "2026-01-01T01:00:00Z", "ISSUE", "uuid-1", "payload-1")
        b2_hash = calculate_block_hash(2, b1_hash, "2026-01-01T02:00:00Z", "ISSUE", "uuid-2", "payload-2")

        blocks = [
            {"block_index": 0, "prev_block_hash": GENESIS_PREV_HASH, "timestamp": "2026-01-01T00:00:00Z", "action": "GENESIS", "doc_uuid": "uuid-0", "payload_hash": "payload-0", "block_hash": b0_hash},
            {"block_index": 1, "prev_block_hash": b0_hash, "timestamp": "2026-01-01T01:00:00Z", "action": "ISSUE", "doc_uuid": "uuid-1", "payload_hash": "payload-1", "block_hash": b1_hash},
            {"block_index": 2, "prev_block_hash": b1_hash, "timestamp": "2026-01-01T02:00:00Z", "action": "ISSUE", "doc_uuid": "uuid-2", "payload_hash": "payload-2", "block_hash": b2_hash},
        ]

        is_valid, broken_idx, reason = verify_audit_chain(blocks)
        self.assertTrue(is_valid)
        self.assertIsNone(broken_idx)

    def test_audit_chain_tamper_detection(self):
        """TC-CRYPTO-08: Altering payload or action in Block 1 must break the audit chain."""
        b0_hash = calculate_block_hash(0, GENESIS_PREV_HASH, "2026-01-01T00:00:00Z", "GENESIS", "uuid-0", "payload-0")
        b1_hash = calculate_block_hash(1, b0_hash, "2026-01-01T01:00:00Z", "ISSUE", "uuid-1", "payload-1")
        b2_hash = calculate_block_hash(2, b1_hash, "2026-01-01T02:00:00Z", "ISSUE", "uuid-2", "payload-2")

        blocks = [
            {"block_index": 0, "prev_block_hash": GENESIS_PREV_HASH, "timestamp": "2026-01-01T00:00:00Z", "action": "GENESIS", "doc_uuid": "uuid-0", "payload_hash": "payload-0", "block_hash": b0_hash},
            {"block_index": 1, "prev_block_hash": b0_hash, "timestamp": "2026-01-01T01:00:00Z", "action": "TAMPERED_ACTION", "doc_uuid": "uuid-1", "payload_hash": "payload-1", "block_hash": b1_hash},
            {"block_index": 2, "prev_block_hash": b1_hash, "timestamp": "2026-01-01T02:00:00Z", "action": "ISSUE", "doc_uuid": "uuid-2", "payload_hash": "payload-2", "block_hash": b2_hash},
        ]

        is_valid, broken_idx, reason = verify_audit_chain(blocks)
        self.assertFalse(is_valid)
        self.assertEqual(broken_idx, 1)

    def test_bit_difference_vector(self):
        """TC-CRYPTO-09: Verify get_bit_difference_vector returns 256 bits matching Hamming distance."""
        from src.crypto.hashing import get_bit_difference_vector
        hash1 = calculate_bytes_hash(b"Original File")
        hash2 = calculate_bytes_hash(b"Tampered File")
        diff_bits, total_bits, _ = count_bit_differences(hash1, hash2)
        vec = get_bit_difference_vector(hash1, hash2)

        self.assertEqual(len(vec), 256)
        self.assertEqual(sum(vec), diff_bits)
        self.assertTrue(all(b in (0, 1) for b in vec))


if __name__ == "__main__":
    unittest.main()
