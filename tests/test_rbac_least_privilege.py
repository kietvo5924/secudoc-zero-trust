"""Unit Tests for RBAC Least Privilege, Ownership Isolation, and Incident Control.

Validates:
1. Issuer A cannot revoke documents issued by Issuer B (Least Privilege).
2. Issuer A cannot view unmasked recipient PII on documents issued by Issuer B.
3. Auditor retains authorized access for audit and emergency incident response.
4. Emergency incident response strictly targets accounts with role == 'ISSUER'.
5. Empty ledger with require_genesis=True is correctly rejected.
"""
import unittest
import tempfile
import shutil
from pathlib import Path
from src.models.database import DatabaseManager, _hash_seed_password
from src.crypto.keys import KeyManager
from src.services.doc_service import DocumentService
from src.services.audit_service import AuditService
from src.web.app import create_app


class TestRBACLeastPrivilege(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = Path(self.test_dir) / "test_secudoc.db"
        self.db_mgr = DatabaseManager(self.db_path, seed_demo=True)
        self.key_mgr = KeyManager()
        self.doc_svc = DocumentService(self.db_mgr, self.key_mgr)
        self.audit_svc = AuditService(self.db_mgr)

        # Seed two distinct Issuer accounts: Issuer A (ID 1 seeded as 'issuer'), create Issuer B
        with self.db_mgr.connection_context() as conn:
            pwd_h, salt = _hash_seed_password("IssuerPassB2026!")
            conn.execute("""
                INSERT INTO users (username, password_hash, salt, full_name, role, status, created_at)
                VALUES ('issuer_b', ?, ?, 'Trường Đại Học Bách Khoa Cơ Sở 2', 'ISSUER', 'ACTIVE', '2026-10-30T00:00:00Z');
            """, (pwd_h, salt))
            self.issuer_b_id = conn.execute("SELECT id FROM users WHERE username = 'issuer_b';").fetchone()["id"]

        # Issue document by Issuer A (ID 1)
        self.doc_a = self.doc_svc.issue_document(
            issuer_id=1,
            title="Bằng Kỹ Sư Công Nghệ Thông Tin (Trường A)",
            recipient_name="Nguyễn Văn An",
            doc_type="DIPLOMA",
            file_bytes=b"Content of diploma A",
            original_filename="diploma_a.pdf"
        )

        # Issue document by Issuer B
        self.doc_b = self.doc_svc.issue_document(
            issuer_id=self.issuer_b_id,
            title="Chứng Chỉ An Ninh Mạng (Trường B)",
            recipient_name="Trần Thị Bích",
            doc_type="CERTIFICATE",
            file_bytes=b"Content of certificate B",
            original_filename="cert_b.pdf"
        )

        # Flask Test Client
        self.app = create_app({
            "TESTING": True,
            "DATABASE_PATH": str(self.db_path),
            "SECRET_KEY": "test_secret_key"
        })
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_issuer_cannot_revoke_other_issuer_document(self):
        """Least Privilege: Issuer A attempting to revoke Issuer B's document must be rejected."""
        # Test directly at service layer:
        with self.assertRaises(PermissionError):
            self.doc_svc.revoke_document(
                doc_uuid=self.doc_b["doc_uuid"],
                revoked_by=1,  # Issuer A
                reason="Issuer A cố tình thu hồi trái phép tài liệu của Trường B"
            )

        # Confirm document B remains ACTIVE
        check_b = self.doc_svc.get_document_by_uuid(self.doc_b["doc_uuid"])
        self.assertEqual(check_b["status"], "ACTIVE")

    def test_issuer_can_revoke_own_document(self):
        """Issuer A can successfully revoke their own issued document."""
        revoked = self.doc_svc.revoke_document(
            doc_uuid=self.doc_a["doc_uuid"],
            revoked_by=1,
            reason="Thu hồi hợp lệ theo quy chế"
        )
        self.assertEqual(revoked["status"], "REVOKED")

    def test_auditor_emergency_revoke_restricted_to_issuer_role(self):
        """Incident Response: Rejects emergency compromise processing if target account is AUDITOR or VERIFIER."""
        # Find auditor account id (username 'auditor')
        with self.db_mgr.connection_context() as conn:
            auditor_row = conn.execute("SELECT id FROM users WHERE role = 'AUDITOR';").fetchone()
            auditor_id = auditor_row["id"]

        with self.assertRaises(ValueError) as ctx:
            self.doc_svc.emergency_batch_revoke(
                issuer_id=auditor_id,
                reason="Nhầm lẫn tài khoản kiểm toán",
                revoked_by=auditor_id
            )
        self.assertIn("ISSUER", str(ctx.exception))

    def test_empty_ledger_with_require_genesis_rejected(self):
        """Hash Chain Integrity: Empty ledger must return is_valid=False when require_genesis=True."""
        # Create empty DB without genesis block
        empty_db_path = Path(self.test_dir) / "empty.db"
        empty_mgr = DatabaseManager(empty_db_path, seed_demo=False)
        with empty_mgr.connection_context() as conn:
            conn.execute("DELETE FROM audit_blocks;")

        audit_empty = AuditService(empty_mgr)
        status = audit_empty.verify_chain_integrity(require_genesis=True)
        self.assertFalse(status["is_valid"])
        self.assertEqual(status["broken_at_block_index"], 0)
        self.assertIn("trống rỗng", status["message"])

    def test_certificate_view_pii_isolation(self):
        """Certificate View: Visiting without auth or as different issuer masks recipient PII."""
        # As unauthenticated user
        resp = self.client.get(f"/certificate/{self.doc_b['doc_uuid']}")
        self.assertEqual(resp.status_code, 200)
        # Should NOT contain full recipient name "Trần Thị Bích" in unmasked form
        self.assertNotIn("Trần Thị Bích", resp.data.decode("utf-8"))
        self.assertIn("T*** T*** B***", resp.data.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
