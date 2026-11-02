"""Unit Tests for Signed Checkpoints and Independent History Verification.

Validates:
1. Cryptographic generation and RSA signature sealing of Checkpoints.
2. Independent verification of untampered checkpoints.
3. Rejection of tampered checkpoints and untrusted keys.
4. Detection of history rollbacks (database restored to past snapshot).
5. Detection of Full-Chain Rewrite attacks (attacker recalculates intermediate block hashes).
"""
import unittest
import tempfile
import shutil
from pathlib import Path
from src.models.database import DatabaseManager
from src.crypto.keys import KeyManager
from src.crypto.checkpoint import (
    create_signed_checkpoint,
    verify_checkpoint_signature,
    verify_ledger_against_checkpoint,
    CHECKPOINT_VERSION
)
from src.services.audit_service import AuditService
from src.services.doc_service import DocumentService


class TestSignedCheckpoint(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = Path(self.test_dir) / "test_checkpoint.db"
        self.db_mgr = DatabaseManager(self.db_path, seed_demo=True)
        self.key_mgr = KeyManager()
        self.doc_svc = DocumentService(self.db_mgr, self.key_mgr)
        self.audit_svc = AuditService(self.db_mgr)

        # Issue 3 sample documents to create multiple sequential blocks
        for i in range(1, 4):
            self.doc_svc.issue_document(
                issuer_id=1,
                title=f"Văn Bản Kiểm Toán #{i}",
                recipient_name=f"Sinh Viên #{i}",
                doc_type="CERTIFICATE",
                file_bytes=f"Nội dung khối #{i}".encode("utf-8"),
                original_filename=f"doc_{i}.pdf"
            )

        self.blocks = self.audit_svc.get_all_audit_blocks()
        self.priv_pem = self.key_mgr.get_private_key_pem()
        self.pub_pem = self.key_mgr.get_public_key_pem(as_bytes=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_and_verify_valid_checkpoint(self):
        """TC-CP-01: Successfully create signed checkpoint and verify against intact ledger."""
        cp = create_signed_checkpoint(
            blocks=self.blocks,
            private_key_pem=self.priv_pem,
            public_key_pem=self.pub_pem,
            sequence=1
        )
        self.assertEqual(cp["version"], CHECKPOINT_VERSION)
        self.assertEqual(cp["sequence"], 1)
        self.assertEqual(cp["total_blocks"], len(self.blocks))
        self.assertEqual(cp["last_block_hash"], self.blocks[-1]["block_hash"])
        self.assertIn("signature", cp)

        # Verify signature
        sig_ok, sig_msg = verify_checkpoint_signature(cp, self.pub_pem)
        self.assertTrue(sig_ok)

        # Verify against live ledger
        report = verify_ledger_against_checkpoint(self.blocks, cp, self.pub_pem)
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["status"], "CHECKPOINT_VERIFIED")

    def test_tampered_checkpoint_metadata_fails_verification(self):
        """TC-CP-02: Modifying any field in checkpoint JSON invalidates digital signature."""
        cp = create_signed_checkpoint(
            blocks=self.blocks,
            private_key_pem=self.priv_pem,
            public_key_pem=self.pub_pem,
            sequence=1
        )
        # Malicious modification: change last_block_hash
        tampered_cp = dict(cp)
        tampered_cp["last_block_hash"] = "0" * 64

        sig_ok, sig_msg = verify_checkpoint_signature(tampered_cp, self.pub_pem)
        self.assertFalse(sig_ok)
        self.assertIn("KHÔNG HỢP LỆ", sig_msg)

    def test_untrusted_public_key_rejected(self):
        """TC-CP-03: Verifying checkpoint with untrusted public key is rejected due to fingerprint mismatch."""
        cp = create_signed_checkpoint(
            blocks=self.blocks,
            private_key_pem=self.priv_pem,
            public_key_pem=self.pub_pem,
            sequence=1
        )
        # Generate an untrusted rogue key pair in temporary folder
        rogue_key_mgr = KeyManager(
            private_path=Path(self.test_dir) / "rogue_priv.pem",
            public_path=Path(self.test_dir) / "rogue_pub.pem"
        )
        rogue_pub = rogue_key_mgr.get_public_key_pem(as_bytes=True)

        sig_ok, sig_msg = verify_checkpoint_signature(cp, rogue_pub)
        self.assertFalse(sig_ok)
        self.assertIn("Fingerprint", sig_msg)

    def test_history_rollback_detection(self):
        """TC-CP-04: Detects database rollback when ledger has fewer blocks than signed checkpoint."""
        cp = create_signed_checkpoint(
            blocks=self.blocks,
            private_key_pem=self.priv_pem,
            public_key_pem=self.pub_pem,
            sequence=1
        )
        # Simulate database rollback: ledger loses last block
        shorter_blocks = self.blocks[:-1]

        report = verify_ledger_against_checkpoint(shorter_blocks, cp, self.pub_pem)
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["status"], "HISTORY_ROLLBACK_DETECTED")
        self.assertIn("Database Rollback", report["message"])

    def test_full_chain_rewrite_attack_detection(self):
        """TC-CP-05: Adversarial Scenario - Full-Chain Rewrite Attack.

        Attacker alters block 1 and re-computes all hashes to head.
        Internal hash chain is FOOLED (is_valid=True), but Signed Checkpoint DETECTS IT!
        """
        # 1. Establish trusted checkpoint before attack
        cp = create_signed_checkpoint(
            blocks=self.blocks,
            private_key_pem=self.priv_pem,
            public_key_pem=self.pub_pem,
            sequence=1
        )

        # 2. Insider executes full-chain rewrite attack modifying block 1
        rewrite_success = self.audit_svc.simulate_full_chain_rewrite(
            tamper_block_index=1,
            tampered_action="INSIDER_ALTERED_PAYLOAD"
        )
        self.assertTrue(rewrite_success)

        # 3. Check internal hash chain: passes because all links were recalculated!
        tampered_blocks = self.audit_svc.get_all_audit_blocks()
        internal_status = self.audit_svc.verify_chain_integrity(require_genesis=True)
        self.assertTrue(internal_status["is_valid"], "Internal chain must be mathematically consistent")

        # 4. Check against external Signed Checkpoint: caught immediately!
        cp_report = verify_ledger_against_checkpoint(tampered_blocks, cp, self.pub_pem)
        self.assertFalse(cp_report["is_valid"])
        self.assertEqual(cp_report["status"], "FULL_CHAIN_REWRITE_DETECTED")
        self.assertIn("FULL-CHAIN REWRITE ATTACK", cp_report["message"])


if __name__ == "__main__":
    unittest.main()
