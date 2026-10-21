"""Integration Tests for Web Application Security, CSRF, RBAC, and Privacy Protections."""
import unittest
import tempfile
import io
import json
from pathlib import Path
from src.web.app import create_app, is_safe_redirect


class TestWebSecurityAndPrivacy(unittest.TestCase):
    """Integration test suite using Flask test client with isolated temp DB and keys."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)
        self.db_path = self.tmp_path / "web_test.db"
        self.sandbox_db_path = self.tmp_path / "web_sandbox.db"

        self.app = create_app({
            "TESTING": True,
            "DATABASE_PATH": str(self.db_path),
            "ATTACK_SANDBOX_DB": str(self.sandbox_db_path),
            "DEMO_MODE": True,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        import gc
        gc.collect()
        try:
            self.tmpdir.cleanup()
        except Exception:
            pass

    def _login_session(self, username="issuer", role="ISSUER", user_id=1):
        """Set up session cookies to simulate authenticated state with a valid CSRF token."""
        with self.client.session_transaction() as sess:
            sess["user"] = {
                "id": user_id,
                "username": username,
                "full_name": f"Test {username.title()}",
                "role": role,
            }
            sess["csrf_token"] = "valid_test_csrf_token_abcdef123456"

    def test_open_redirect_protection(self):
        """TC-WEB-01: Login redirects reject external URLs and protocol-relative links."""
        self.assertFalse(is_safe_redirect("http://evil.com"))
        self.assertFalse(is_safe_redirect("https://evil.com/phish"))
        self.assertFalse(is_safe_redirect("//evil.com"))
        self.assertFalse(is_safe_redirect("javascript:alert(1)"))
        self.assertFalse(is_safe_redirect(r"\evil.com"))
        self.assertTrue(is_safe_redirect("/dashboard"))
        self.assertTrue(is_safe_redirect("/audit"))

        # Test login POST with malicious next parameter
        # First get login page to establish session CSRF token
        get_res = self.client.get("/login")
        with self.client.session_transaction() as sess:
            token = sess["csrf_token"]

        login_res = self.client.post("/login", data={
            "csrf_token": token,
            "username": "issuer",
            "password": "IssuerSecurePass2026!",
            "next": "//evil.com"
        })
        # Should redirect to /dashboard, not //evil.com
        self.assertEqual(login_res.status_code, 302)
        self.assertTrue(login_res.headers["Location"].endswith("/dashboard"))

    def test_csrf_rejection_on_post(self):
        """TC-WEB-02: State-changing POST endpoints reject requests missing CSRF token."""
        self._login_session("auditor", "AUDITOR")

        # POST without csrf_token to API returns 400 Bad Request
        res_attack = self.client.post("/api/attack/tamper-db", json={
            "block_index": 0,
            "field": "action",
            "malicious_value": "TAMPERED"
        })
        self.assertEqual(res_attack.status_code, 400)
        self.assertIn("CSRF", res_attack.get_json()["message"])

        # POST with valid X-CSRFToken is accepted
        res_valid_csrf = self.client.post(
            "/api/attack/tamper-db",
            json={
                "block_index": 0,
                "field": "action",
                "malicious_value": "ATTACK_FORGED"
            },
            headers={"X-CSRFToken": "valid_test_csrf_token_abcdef123456"}
        )
        self.assertEqual(res_valid_csrf.status_code, 200)

    def test_rbac_access_control(self):
        """TC-WEB-03: RBAC enforces role boundaries across routes (401 unauthenticated, 403 unauthorized)."""
        # 1. Unauthenticated access to protected route redirects to login
        res_unauth = self.client.get("/dashboard")
        self.assertEqual(res_unauth.status_code, 302)
        self.assertIn("/login", res_unauth.headers["Location"])

        # 2. AUDITOR role cannot access ISSUER-only /dashboard route (HTTP 403)
        self._login_session("auditor", "AUDITOR", user_id=2)
        res_auditor = self.client.get("/dashboard")
        self.assertEqual(res_auditor.status_code, 403)

        # 3. ISSUER role cannot access AUDITOR-only /audit route (HTTP 403)
        self._login_session("issuer", "ISSUER", user_id=1)
        res_issuer = self.client.get("/audit")
        self.assertEqual(res_issuer.status_code, 403)

    def test_privacy_mode_verify_hash_api(self):
        """TC-WEB-04: /api/verify-hash verifies authentic document using only hash without file bytes."""
        # Issue document via internal service
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Privacy Guarded Transcript",
            recipient_name="Pham Minh Test",
            doc_type="TRANSCRIPT",
            file_bytes=b"CONFIDENTIAL TRANSCRIPT FILE CONTENT",
            original_filename="transcript.txt"
        )

        # Client sends only SHA-256 hash
        res = self.client.post("/api/verify-hash", json={
            "hash": doc["doc_hash"],
            "uuid": doc["doc_uuid"]
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "VERIFIED_AUTHENTIC")
        self.assertTrue(data["is_authentic"])

    def test_homepage_masks_recipient_pii(self):
        """TC-WEB-05: Homepage document listing masks recipient personal data (e.g. Nguyen Van An -> N*** V*** A***)."""
        self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Bang Tot Nghiep Public",
            recipient_name="Nguyen Van An",
            doc_type="DIPLOMA",
            file_bytes=b"Public Diploma File Content",
            original_filename="diploma.pdf"
        )

        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        # Full plain name must NOT appear in the rendered HTML
        self.assertNotIn("Nguyen Van An", html)
        # Masked name MUST appear
        self.assertIn("N*** V*** A***", html)

    def test_trust_info_endpoint(self):
        """TC-WEB-06: /api/trust-info returns root public key fingerprint and prototype limitations."""
        res = self.client.get("/api/trust-info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["root_public_key_fingerprint"].startswith("SHA256:"))
        self.assertIn("prototype", data["trust_model"].lower())
        self.assertIn("limitations", data)

    def test_attack_lab_sandbox_isolation(self):
        """TC-WEB-07: Attack Lab mutations only affect the sandbox DB, leaving the runtime DB untouched."""
        # Count initial blocks in both DBs
        main_blocks = self.app.audit_svc.get_all_audit_blocks()
        initial_main_len = len(main_blocks)

        self._login_session("auditor", "AUDITOR")
        # Tamper block 0 in sandbox DB via Attack Lab endpoint
        res = self.client.post(
            "/api/attack/tamper-db",
            json={"block_index": 0, "field": "action", "malicious_value": "ATTACK_FORGED"},
            headers={"X-CSRFToken": "valid_test_csrf_token_abcdef123456"}
        )
        self.assertEqual(res.status_code, 200)

        # Sandbox DB must reflect the tamper
        sandbox_blocks = self.app.sandbox_audit_svc.get_all_audit_blocks()
        self.assertEqual(sandbox_blocks[0]["action"], "ATTACK_FORGED")

        # Main DB must remain completely untouched
        main_blocks_after = self.app.audit_svc.get_all_audit_blocks()
        self.assertEqual(len(main_blocks_after), initial_main_len)
        self.assertEqual(main_blocks_after[0]["action"], "GENESIS")


if __name__ == "__main__":
    unittest.main()
