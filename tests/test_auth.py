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

    def test_failed_login_lockout(self):
        """TC-AUTH-04: Exceeding LOGIN_MAX_FAILED_ATTEMPTS locks out the IP/username."""
        test_ip = "192.168.1.100"
        self.auth_svc.reset_failures(test_ip)

        # Attempt 5 failed logins
        for _ in range(5):
            res = self.auth_svc.authenticate("issuer", "WrongPassword!", client_ip=test_ip)
            self.assertIsNone(res)

        # 6th attempt must be locked out with PermissionError
        with self.assertRaises(PermissionError) as ctx:
            self.auth_svc.authenticate("issuer", "IssuerSecurePass2026!", client_ip=test_ip)
        self.assertIn("Quá nhiều lần đăng nhập thất bại", str(ctx.exception))

        # Resetting failures lifts the lockout
        self.auth_svc.reset_failures(test_ip)
        valid = self.auth_svc.authenticate("issuer", "IssuerSecurePass2026!", client_ip=test_ip)
        self.assertIsNotNone(valid)

    def test_demo_mode_suppression(self):
        """TC-AUTH-05: DatabaseManager does not seed demo users when DEMO_MODE is False."""
        no_seed_db_path = Path(self.tmpdir.name) / "no_seed.db"
        no_seed_mgr = DatabaseManager(no_seed_db_path, seed_demo=False)

        with no_seed_mgr.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM users;")
            row = cursor.fetchone()
            self.assertEqual(row["cnt"], 0)

    def test_locked_or_compromised_user_cannot_authenticate(self):
        """TC-AUTH-06: A user with status 'COMPROMISED' or 'LOCKED' cannot authenticate."""
        # Lock user 1
        self.auth_svc.lock_user(user_id=1, status="COMPROMISED")

        with self.assertRaises(PermissionError) as ctx:
            self.auth_svc.authenticate("issuer", "IssuerSecurePass2026!")
        self.assertIn("đã bị khóa do sự cố an ninh", str(ctx.exception))

    def test_auth_service_lock_user(self):
        """TC-AUTH-07: lock_user correctly updates user status in database."""
        success = self.auth_svc.lock_user(user_id=2, status="LOCKED")
        self.assertTrue(success)
        user = self.auth_svc.get_user_by_id(2)
        self.assertIsNotNone(user)
        self.assertEqual(user["status"], "LOCKED")


if __name__ == "__main__":
    unittest.main()
