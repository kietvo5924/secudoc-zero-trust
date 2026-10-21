"""Integration Tests for the Zero-Trust Verification Pipeline."""
import unittest
import tempfile
from pathlib import Path
from src.services.doc_service import DocumentService
from src.services.verify_engine import VerificationEngine
from src.crypto.keys import KeyManager
from src.models.database import DatabaseManager


class TestVerificationPipeline(unittest.TestCase):
    """Test suite for the Zero-Trust verification states and diagnostics."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_verify.db"
        self.key_dir = Path(self.tmpdir.name) / "keys"
        self.db_mgr = DatabaseManager(self.db_path)
        self.key_mgr = KeyManager(
            private_path=self.key_dir / "priv.pem",
            public_path=self.key_dir / "pub.pem"
        )
        self.doc_svc = DocumentService(self.db_mgr, self.key_mgr)
        self.verify_engine = VerificationEngine(self.doc_svc, self.key_mgr, self.db_mgr)

        # Issue a reference document
        self.original_bytes = b"BACH KHOA UNIVERSITY - OFFICIAL TRANSCRIPT - GPA 4.00"
        self.doc = self.doc_svc.issue_document(
            issuer_id=1,
            title="Bang Diem Chinh Thuc",
            recipient_name="Pham Minh Test",
            doc_type="TRANSCRIPT",
            file_bytes=self.original_bytes,
            original_filename="transcript.txt"
        )

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.tmpdir.cleanup()
        except Exception:
            pass

    def test_happy_path_verification(self):
        """TC-VERIFY-01: Authentic file produces VERIFIED_AUTHENTIC with valid signature."""
        res = self.verify_engine.verify_document(self.original_bytes)
        self.assertEqual(res["status"], "VERIFIED_AUTHENTIC")
        self.assertTrue(res["signature_valid"])
        self.assertEqual(res["computed_hash"], self.doc["doc_hash"])

    def test_tampered_content_detection(self):
        """TC-VERIFY-02: Modifying 1 byte in the file produces TAMPERED_CONTENT."""
        # Flip 1 byte
        tampered_bytes = bytearray(self.original_bytes)
        tampered_bytes[0] ^= 0x01

        # When verifying against claimed UUID
        res = self.verify_engine.verify_document(bytes(tampered_bytes), claimed_uuid=self.doc["doc_uuid"])
        self.assertEqual(res["status"], "TAMPERED_CONTENT")
        self.assertFalse(res["signature_valid"])
        self.assertNotEqual(res["computed_hash"], res["expected_hash"])

    def test_revoked_document_detection(self):
        """TC-VERIFY-03: An authentic file whose document has been revoked produces REVOKED."""
        self.doc_svc.revoke_document(
            doc_uuid=self.doc["doc_uuid"],
            revoked_by=1,
            reason="Diploma revoked due to fraudulent admission records"
        )

        res = self.verify_engine.verify_document(self.original_bytes)
        self.assertEqual(res["status"], "REVOKED")
        self.assertTrue(res["signature_valid"]) # Signature was valid, but revoked in ledger
        self.assertEqual(res["revocation_reason"], "Diploma revoked due to fraudulent admission records")

    def test_unregistered_document_detection(self):
        """TC-VERIFY-04: Completely unknown file produces NOT_FOUND."""
        random_bytes = b"Some random unverified file not in database"
        res = self.verify_engine.verify_document(random_bytes)
        self.assertEqual(res["status"], "NOT_FOUND")
        self.assertIsNone(res["expected_hash"])

    def test_corrupted_signature_detection(self):
        """TC-VERIFY-05: Modifying signature in DB causes INVALID_SIGNATURE verdict."""
        # Directly corrupt signature in SQLite
        with self.db_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE documents SET signature = ? WHERE doc_uuid = ?;",
                ("f" * 512, self.doc["doc_uuid"])
            )


        res = self.verify_engine.verify_document(self.original_bytes)
        self.assertEqual(res["status"], "INVALID_SIGNATURE")
        self.assertFalse(res["signature_valid"])


    def test_verify_hash_privacy(self):
        """TC-VERIFY-06: Privacy-Preserving verify_hash evaluates authentic document with 0 raw bytes uploaded."""
        authentic_hash = self.doc["doc_hash"]
        res = self.verify_engine.verify_hash(authentic_hash)
        self.assertEqual(res["status"], "VERIFIED_AUTHENTIC")
        self.assertTrue(res["signature_valid"])
        self.assertEqual(res["computed_hash"], authentic_hash)

        # Unknown hash produces NOT_FOUND
        fake_hash = "a" * 64
        fake_res = self.verify_engine.verify_hash(fake_hash)
        self.assertEqual(fake_res["status"], "NOT_FOUND")


    def test_metadata_tampering_recipient_name(self):
        """TC-VERIFY-07: Tampering recipient name in DB invalidates canonical signature."""
        with self.db_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE documents SET recipient_name = ? WHERE doc_uuid = ?;",
                ("Hacker Tampered Name", self.doc["doc_uuid"])
            )

        res = self.verify_engine.verify_document(self.original_bytes)
        self.assertEqual(res["status"], "INVALID_SIGNATURE")
        self.assertFalse(res["signature_valid"])
        self.assertIn("chữ ký", res["verdict_title"].lower())

    def test_revocation_conflict_detection(self):
        """TC-VERIFY-08: Maliciously setting status='ACTIVE' when revoked in ledger triggers REVOCATION_CONFLICT."""
        # 1. Revoke legitimately
        self.doc_svc.revoke_document(
            doc_uuid=self.doc["doc_uuid"],
            revoked_by=1,
            reason="Violation of examination rules"
        )

        # 2. Malicious admin updates documents status back to ACTIVE directly in SQLite
        with self.db_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE documents SET status = 'ACTIVE' WHERE doc_uuid = ?;",
                (self.doc["doc_uuid"],)
            )

        res = self.verify_engine.verify_document(self.original_bytes)
        self.assertEqual(res["status"], "REVOCATION_CONFLICT")
        self.assertFalse(res["is_authentic"])

    def test_broken_audit_chain_detection(self):
        """TC-VERIFY-09: Corrupting an audit block in SQLite causes verification engine to flag AUDIT_CHAIN_BROKEN."""
        with self.db_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE audit_blocks SET action = 'TAMPERED_ACTION' WHERE block_index = 0;"
            )

        res = self.verify_engine.verify_document(self.original_bytes)
        self.assertEqual(res["status"], "AUDIT_CHAIN_BROKEN")
        self.assertFalse(res["is_authentic"])


if __name__ == "__main__":
    unittest.main()
