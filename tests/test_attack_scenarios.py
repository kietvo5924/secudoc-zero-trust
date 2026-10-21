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


if __name__ == "__main__":
    unittest.main()
