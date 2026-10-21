"""Unit Tests for Authentication, PBKDF2 Password Security, and RBAC."""
import unittest
import tempfile
from pathlib import Path
from src.services.auth_service import hash_password, verify_password, AuthService
from src.models.database import DatabaseManager


class TestAuthAndRBAC(unittest.TestCase):
    """Test suite for credential verification and access control."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_auth.db"
        self.db_mgr = DatabaseManager(self.db_path)
        self.auth_svc = AuthService(self.db_mgr)

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.tmpdir.cleanup()
        except Exception:
            pass

    def test_pbkdf2_hash_and_verify(self):
        """TC-AUTH-01: Correct password verifies successfully; incorrect password fails."""
        raw_pass = "MySecretPassword2026!"
        pwd_hash, salt = hash_password(raw_pass)

        self.assertIsInstance(pwd_hash, str)
        self.assertIsInstance(salt, str)
        self.assertEqual(len(pwd_hash), 64) # SHA-256 output = 64 hex chars
        self.assertEqual(len(salt), 32)     # 16 bytes = 32 hex chars

        # Verification with correct password
        self.assertTrue(verify_password(raw_pass, pwd_hash, salt))

        # Verification with incorrect password
        self.assertFalse(verify_password("WrongPassword!", pwd_hash, salt))
        self.assertFalse(verify_password("", pwd_hash, salt))

    def test_unique_salts_for_identical_passwords(self):
        """TC-AUTH-02: Hashing identical passwords produces completely different salts and hashes."""
        pass1 = "AdminPassword123"
        hash1, salt1 = hash_password(pass1)
        hash2, salt2 = hash_password(pass1)

        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hash1, hash2)

    def test_auth_service_seeded_accounts(self):
        """TC-AUTH-03: Seeded demo accounts authenticate properly."""
        # Test issuer account
        user = self.auth_svc.authenticate("issuer", "IssuerSecurePass2026!")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "issuer")
        self.assertEqual(user["role"], "ISSUER")

        # Test auditor account
        auditor = self.auth_svc.authenticate("auditor", "AuditorPass2026!")
        self.assertIsNotNone(auditor)
        self.assertEqual(auditor["role"], "AUDITOR")

        # Test invalid password
        invalid = self.auth_svc.authenticate("issuer", "WrongPassword")
        self.assertIsNone(invalid)

        # Test non-existent user
        non_existent = self.auth_svc.authenticate("unknown_user", "AnyPassword")
        self.assertIsNone(non_existent)


if __name__ == "__main__":
    unittest.main()
