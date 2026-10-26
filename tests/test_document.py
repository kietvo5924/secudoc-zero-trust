"""Unit and Integration Tests for Document Ingestion, Signing, Issuance, and Sanitization."""
import unittest
import tempfile
from pathlib import Path
from src.services.doc_service import DocumentService, sanitize_filename
from src.crypto.keys import KeyManager
from src.models.database import DatabaseManager


class TestDocumentService(unittest.TestCase):
    """Test suite for document issuance, storage isolation, and revocation."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_doc.db"
        self.key_dir = Path(self.tmpdir.name) / "keys"
        self.db_mgr = DatabaseManager(self.db_path)
        self.key_mgr = KeyManager(
            private_path=self.key_dir / "priv.pem",
            public_path=self.key_dir / "pub.pem"
        )
        self.doc_svc = DocumentService(self.db_mgr, self.key_mgr)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.tmpdir.cleanup()
        except Exception:
            pass

    def test_sanitize_filename_prevents_path_traversal(self):
        """TC-DOC-01: Path traversal payloads (../../etc/passwd) must be stripped safely."""
        malicious_input = "../../../etc/passwd.pdf"
        sanitized = sanitize_filename(malicious_input)
        self.assertNotIn("/", sanitized)
        self.assertNotIn("\\", sanitized)
        self.assertNotIn("..", sanitized)
        self.assertTrue(sanitized.endswith(".pdf"))

    def test_empty_file_rejected(self):
        """TC-DOC-02: Issuing a 0-byte file must raise ValueError."""
        with self.assertRaises(ValueError):
            self.doc_svc.issue_document(
                issuer_id=1,
                title="Empty Document",
                recipient_name="Test Student",
                doc_type="CERTIFICATE",
                file_bytes=b"",
                original_filename="empty.pdf"
            )

    def test_issue_document_creates_record_and_audit_block(self):
        """TC-DOC-03: Issuing a document creates DB record and appends to audit ledger."""
        sample_bytes = b"Official University Diploma for Test Student 2026"
        doc = self.doc_svc.issue_document(
            issuer_id=1,
            title="Bang Tot Nghiep K60",
            recipient_name="Nguyen Van Test",
            doc_type="DIPLOMA",
            file_bytes=sample_bytes,
            original_filename="diploma.pdf"
        )

        self.assertIsNotNone(doc)
        self.assertEqual(doc["status"], "ACTIVE")
        self.assertEqual(len(doc["doc_hash"]), 64)
        self.assertEqual(len(doc["signature"]), 512)

        # Verify audit ledger has appended a new ISSUE block
        with self.db_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_blocks WHERE doc_uuid = ?;", (doc["doc_uuid"],))
            block = cursor.fetchone()
            self.assertIsNotNone(block)
            self.assertEqual(block["action"], "ISSUE")
            self.assertEqual(block["payload_hash"], doc["doc_hash"])


    def test_revoke_document_updates_status_and_appends_block(self):
        """TC-DOC-04: Revoking an active document updates status to REVOKED and adds audit block."""
        sample_bytes = b"Temporary Certificate"
        doc = self.doc_svc.issue_document(
            issuer_id=1,
            title="Temporary Cert",
            recipient_name="Le Van Test",
            doc_type="CERTIFICATE",
            file_bytes=sample_bytes,
            original_filename="temp_cert.pdf"
        )

        revoked_doc = self.doc_svc.revoke_document(
            doc_uuid=doc["doc_uuid"],
            revoked_by=1,
            reason="Violation of examination regulations"
        )

        self.assertEqual(revoked_doc["status"], "REVOKED")
        self.assertEqual(revoked_doc["revocation_reason"], "Violation of examination regulations")

        # Verify REVOKE audit block
        with self.db_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_blocks WHERE doc_uuid = ? AND action = 'REVOKE';", (doc["doc_uuid"],))
            block = cursor.fetchone()
            self.assertIsNotNone(block)

    def test_emergency_batch_revoke_when_issuer_compromised(self):
        """TC-DOC-05: Incident Response - Batch revoke active documents when issuer account is compromised."""
        doc1 = self.doc_svc.issue_document(
            issuer_id=1,
            title="Bằng Cử Nhân 1",
            recipient_name="Sinh Viên A",
            doc_type="DIPLOMA",
            file_bytes=b"Diploma 1",
            original_filename="d1.txt"
        )
        doc2 = self.doc_svc.issue_document(
            issuer_id=1,
            title="Bằng Cử Nhân 2",
            recipient_name="Sinh Viên B",
            doc_type="DIPLOMA",
            file_bytes=b"Diploma 2",
            original_filename="d2.txt"
        )

        revoked_uuids = self.doc_svc.emergency_batch_revoke(
            issuer_id=1,
            reason="Tài khoản Issuer bị rò rỉ thông tin đăng nhập trong sự cố an ninh",
            revoked_by=1
        )

        self.assertIn(doc1["doc_uuid"], revoked_uuids)
        self.assertIn(doc2["doc_uuid"], revoked_uuids)

        # Confirm all are now REVOKED in database
        check1 = self.doc_svc.get_document_by_uuid(doc1["doc_uuid"])
        check2 = self.doc_svc.get_document_by_uuid(doc2["doc_uuid"])
        self.assertEqual(check1["status"], "REVOKED")
        self.assertEqual(check2["status"], "REVOKED")
        self.assertIn("TÀI KHOẢN BỊ XÂM PHẠM", check1["revocation_reason"])


if __name__ == "__main__":
    unittest.main()

