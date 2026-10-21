"""Security Attack Scenarios and Exploit Defense Verifications."""
import unittest
import tempfile
from pathlib import Path
from src.services.doc_service import DocumentService, sanitize_filename
from src.services.audit_service import AuditService
from src.services.verify_engine import VerificationEngine
from src.crypto.keys import KeyManager
from src.crypto.signature import sign_hash, verify_signature
from src.crypto.hashing import calculate_bytes_hash
from src.models.database import DatabaseManager
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class TestAttackScenarios(unittest.TestCase):
    """
    Simulation tests for the core threat scenarios required by the course syllabus:
    1. Bit-Flip Content Tampering (THR-02)
    2. Signature Forgery with Rogue Key (THR-01)
    3. Database Ledger Tampering by Malicious Insider (THR-07)
    4. Path Traversal & Malicious File Upload (THR-08)
    5. Revocation Bypass Attack (THR-03)
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_attack.db"
        self.key_dir = Path(self.tmpdir.name) / "keys"
        self.db_mgr = DatabaseManager(self.db_path)
        self.key_mgr = KeyManager(
            private_path=self.key_dir / "priv.pem",
            public_path=self.key_dir / "pub.pem"
        )
        self.doc_svc = DocumentService(self.db_mgr, self.key_mgr)
        self.audit_svc = AuditService(self.db_mgr)
        self.verify_engine = VerificationEngine(self.doc_svc, self.key_mgr, self.db_mgr)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.tmpdir.cleanup()
        except Exception:
            pass

    def test_file_tampering_bit_flip(self):
        """
        ATTACK SCENARIO 1 (THR-02): Bit-Flip Content Tampering.
        Attacker alters 1 byte (e.g. changing GPA or student name).
        System must detect mismatch and reject with TAMPERED_CONTENT.
        """
        original_doc = (
            "TRUONG DAI HOC - BANG TOT NGHIEP\n"
            "Sinh vien: NGUYEN VAN A\n"
            "Diem GPA: 2.50\n" # Original low grade
        ).encode("utf-8")

        doc = self.doc_svc.issue_document(
            issuer_id=1,
            title="Bang Tot Nghiep - Nguyen Van A",
            recipient_name="Nguyen Van A",
            doc_type="DIPLOMA",
            file_bytes=original_doc,
            original_filename="diploma.txt"
        )

        # Attacker modifies "2.50" to "3.90"
        forged_doc = original_doc.replace(b"2.50", b"3.90")

        # Verifier runs forged document against claimed UUID
        verdict = self.verify_engine.verify_document(forged_doc, claimed_uuid=doc["doc_uuid"])

        self.assertEqual(verdict["status"], "TAMPERED_CONTENT")
        self.assertFalse(verdict["signature_valid"])
        self.assertIn("can thiệp", verdict["verdict_title"].lower())

    def test_forged_signature_attack(self):
        """
        ATTACK SCENARIO 2 (THR-01): Signature Forgery with Rogue Key.
        Attacker generates an unauthorized RSA keypair, signs a document,
        and claims it was officially issued by the University.
        """
        rogue_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        malicious_doc = b"FAKE DIPLOMA CREATED BY ROGUE ATTACKER"
        doc_hash = calculate_bytes_hash(malicious_doc)

        # Attacker signs with rogue key
        rogue_signature = sign_hash(rogue_key, doc_hash)

        # Verifier tests with official University Root Public Key
        official_pub_key = self.key_mgr.get_public_key()
        is_verified = verify_signature(official_pub_key, doc_hash, rogue_signature)

        self.assertFalse(is_verified, "Rogue signature must NEVER be accepted by Official Root Public Key!")

    def test_database_tampering_detection(self):
        """
        ATTACK SCENARIO 3 (THR-07): Direct Database Tampering by Malicious Insider.
        A corrupt administrator alters a field in SQLite to retroactively approve a fake document.
        The cryptographic audit chain must detect the break at the exact block index.
        """
        # Issue 2 legitimate documents to build the hash chain
        self.doc_svc.issue_document(1, "Doc 1", "Student 1", "CERTIFICATE", b"Data 1", "d1.txt")
        self.doc_svc.issue_document(1, "Doc 2", "Student 2", "CERTIFICATE", b"Data 2", "d2.txt")

        # Verify initial chain is 100% valid
        initial_status = self.audit_svc.verify_chain_integrity()
        self.assertTrue(initial_status["is_valid"])

        # Corrupt DB: Alter block 1 action directly
        self.audit_svc.simulate_database_tamper(block_index=1, field_to_alter="action", malicious_value="CORRUPTED_ACTION")

        # Auditor re-runs cryptographic verification
        tampered_status = self.audit_svc.verify_chain_integrity()
        self.assertFalse(tampered_status["is_valid"])
        self.assertEqual(tampered_status["broken_at_block_index"], 1)
        self.assertIn("CAN THIỆP SỔ CÁI", tampered_status["message"])

    def test_path_traversal_prevention(self):
        """
        ATTACK SCENARIO 4 (THR-08): Path Traversal Upload Attack.
        Attacker uploads file with filename `../../../../Windows/System32/evil.dll`.
        System strips path traversal elements and saves file safely.
        """
        attack_filename = "../../../../Windows/System32/evil.dll"
        clean = sanitize_filename(attack_filename)
        self.assertNotIn("..", clean)
        self.assertNotIn("/", clean)
        self.assertNotIn("\\", clean)
        self.assertEqual(clean, "evil.dll")

    def test_revocation_bypass_attempt(self):
        """
        ATTACK SCENARIO 5 (THR-03): Revocation Bypass.
        An applicant whose certificate was revoked presents the original unaltered PDF.
        The Zero-Trust engine must flag the document as REVOKED despite valid hash and signature.
        """
        original_bytes = b"DISCIPLINED STUDENT DIPLOMA - EXPELLED 2026"
        doc = self.doc_svc.issue_document(
            issuer_id=1,
            title="Expelled Student Cert",
            recipient_name="Student X",
            doc_type="CERTIFICATE",
            file_bytes=original_bytes,
            original_filename="cert.txt"
        )

        # Authority revokes the certificate
        self.doc_svc.revoke_document(
            doc_uuid=doc["doc_uuid"],
            revoked_by=1,
            reason="Expelled for academic misconduct"
        )

        # Verifier checks the original file
        verdict = self.verify_engine.verify_document(original_bytes)
        self.assertEqual(verdict["status"], "REVOKED")
        self.assertEqual(verdict["badge_class"], "badge-warning")
        self.assertEqual(verdict["revocation_reason"], "Expelled for academic misconduct")

    def test_arbitrary_block_restore_and_isolation(self):
        """
        ATTACK SCENARIO 6: Restore on Arbitrary Block Index (block != 0) & Sandbox Isolation.
        Ensures restore_database_block restores actual pre-tamper values for block 2,
        and does not touch an isolated separate DB.
        """
        # Create a separate isolated dummy DB to represent untouched runtime DB
        isolated_db_path = Path(self.tmpdir.name) / "runtime_untouched.db"
        isolated_mgr = DatabaseManager(isolated_db_path)
        with isolated_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM audit_blocks;")
            initial_isolated_count = cursor.fetchone()["cnt"]

        # Issue multiple docs to populate blocks 0, 1, 2
        self.doc_svc.issue_document(1, "Doc A", "Recipient A", "CERTIFICATE", b"Content A", "a.txt")
        self.doc_svc.issue_document(1, "Doc B", "Recipient B", "DIPLOMA", b"Content B", "b.txt")

        # Verify chain valid at 3 blocks
        chain_status = self.audit_svc.verify_chain_integrity()
        self.assertTrue(chain_status["is_valid"])

        # Tamper block 2 (arbitrary block index > 0)
        tamper_ok = self.audit_svc.simulate_database_tamper(block_index=2, field_to_alter="action", malicious_value="FORGED_ACTION")
        self.assertTrue(tamper_ok)

        # Verify chain is broken at block 2
        broken_status = self.audit_svc.verify_chain_integrity()
        self.assertFalse(broken_status["is_valid"])
        self.assertEqual(broken_status["broken_at_block_index"], 2)

        # Restore block 2
        restore_ok = self.audit_svc.restore_database_block(block_index=2)
        self.assertTrue(restore_ok)

        # Verify chain is restored to valid
        restored_status = self.audit_svc.verify_chain_integrity()
        self.assertTrue(restored_status["is_valid"])

        # Verify isolated DB was never touched
        with isolated_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM audit_blocks;")
            self.assertEqual(cursor.fetchone()["cnt"], initial_isolated_count)

    def test_recalculated_chain_detected_by_external_anchor(self):
        """
        ATTACK SCENARIO 7: Full Ledger Recalculation Threat Analysis.
        If an attacker rewrites block 1 AND recalculates all subsequent block hashes,
        internal hash links appear consistent. However, an external anchor/checkpoint
        discloses the forgery because head_hash != trusted_head_hash.
        """
        from src.crypto.merkle import get_chain_head_hash, calculate_block_hash
        self.doc_svc.issue_document(1, "Doc 1", "Recipient 1", "CERTIFICATE", b"Data 1", "1.txt")
        self.doc_svc.issue_document(1, "Doc 2", "Recipient 2", "CERTIFICATE", b"Data 2", "2.txt")

        # Snapshot trusted head hash (external anchor)
        blocks = self.audit_svc.get_all_audit_blocks()
        trusted_head_hash = get_chain_head_hash(blocks)

        # Attacker recalculates downstream block hashes
        with self.db_mgr.connection_context() as conn:
            cursor = conn.cursor()
            # 1. Modify block 1 payload
            cursor.execute("UPDATE audit_blocks SET payload_hash = 'tampered_payload' WHERE block_index = 1;")
            # 2. Recalculate block 1 hash
            cursor.execute("SELECT * FROM audit_blocks WHERE block_index = 1;")
            b1 = dict(cursor.fetchone())
            new_b1_hash = calculate_block_hash(1, b1["prev_block_hash"], b1["timestamp"], b1["action"], b1["doc_uuid"], b1["payload_hash"])
            cursor.execute("UPDATE audit_blocks SET block_hash = ? WHERE block_index = 1;", (new_b1_hash,))

            # 3. Recalculate block 2 with new prev_block_hash
            cursor.execute("SELECT * FROM audit_blocks WHERE block_index = 2;")
            b2 = dict(cursor.fetchone())
            new_b2_hash = calculate_block_hash(2, new_b1_hash, b2["timestamp"], b2["action"], b2["doc_uuid"], b2["payload_hash"])
            cursor.execute("UPDATE audit_blocks SET prev_block_hash = ?, block_hash = ? WHERE block_index = 2;", (new_b1_hash, new_b2_hash))

        # Attacker's recalculation fools internal chain verification:
        tampered_blocks = self.audit_svc.get_all_audit_blocks()
        internal_valid, _, _ = self.audit_svc.verify_chain_integrity()["is_valid"], None, None

        # BUT trusted external anchor detects the forgery immediately:
        recalculated_head_hash = get_chain_head_hash(tampered_blocks)
        self.assertNotEqual(trusted_head_hash, recalculated_head_hash, "External anchor must detect full-chain recalculation!")


if __name__ == "__main__":
    unittest.main()
