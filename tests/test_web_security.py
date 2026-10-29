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

    def test_unauthenticated_download_rejected(self):
        """TC-WEB-08: Unauthenticated access to /download/<doc_uuid> is rejected (redirects to login)."""
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Confidential File",
            recipient_name="Student Test",
            doc_type="CERTIFICATE",
            file_bytes=b"CONFIDENTIAL_PAYLOAD_BYTES",
            original_filename="secret.pdf"
        )
        res = self.client.get(f"/download/{doc['doc_uuid']}")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

    def test_unauthorized_download_by_verifier_rejected(self):
        """TC-WEB-09: PUBLIC_VERIFIER role cannot download raw documents (HTTP 403 Forbidden)."""
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Diploma File",
            recipient_name="Student A",
            doc_type="DIPLOMA",
            file_bytes=b"DIPLOMA_PAYLOAD",
            original_filename="diploma.pdf"
        )
        self._login_session("verifier", "PUBLIC_VERIFIER", user_id=3)
        res = self.client.get(f"/download/{doc['doc_uuid']}")
        self.assertEqual(res.status_code, 403)

    def test_issuer_cannot_download_other_issuer_document(self):
        """TC-WEB-10: Issuer B cannot download a document issued by Issuer A (IDOR prevention, HTTP 403)."""
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Issuer A File",
            recipient_name="Student B",
            doc_type="CERTIFICATE",
            file_bytes=b"ISSUER_A_BYTES",
            original_filename="doc_a.pdf"
        )
        # Login as Issuer 2
        self._login_session("issuer2", "ISSUER", user_id=2)
        res = self.client.get(f"/download/{doc['doc_uuid']}")
        self.assertEqual(res.status_code, 403)

    def test_authorized_issuer_and_auditor_can_download_document(self):
        """TC-WEB-11: Owning issuer and auditor can download the authentic binary file."""
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Authorized Download File",
            recipient_name="Student C",
            doc_type="CERTIFICATE",
            file_bytes=b"AUTHORIZED_CONTENT",
            original_filename="doc_c.pdf"
        )
        # Owning Issuer 1
        self._login_session("issuer", "ISSUER", user_id=1)
        res_owner = self.client.get(f"/download/{doc['doc_uuid']}")
        self.assertEqual(res_owner.status_code, 200)
        self.assertEqual(res_owner.data, b"AUTHORIZED_CONTENT")
        res_owner.close()

        # Auditor
        self._login_session("auditor", "AUDITOR", user_id=2)
        res_auditor = self.client.get(f"/download/{doc['doc_uuid']}")
        self.assertEqual(res_auditor.status_code, 200)
        self.assertEqual(res_auditor.data, b"AUTHORIZED_CONTENT")
        res_auditor.close()

    def test_unauthenticated_certificate_view_masks_pii_and_uuid(self):
        """TC-WEB-12: Unauthenticated view of /certificate/<doc_uuid> masks recipient PII and does not leak storage path."""
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Confidential Certificate",
            recipient_name="Nguyen Van Chuyen",
            doc_type="CERTIFICATE",
            file_bytes=b"CERT_BYTES",
            original_filename="cert.pdf"
        )
        res = self.client.get(f"/certificate/{doc['doc_uuid']}")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        # Full name must NOT appear in HTML
        self.assertNotIn("Nguyen Van Chuyen", html)
        self.assertIn("N*** V*** C***", html)
        # file_storage_path must NEVER be exposed
        self.assertNotIn("file_storage_path", html)
        self.assertNotIn(".bin", html)

    def test_attack_lab_does_not_leak_real_doc_uuids_or_recipients(self):
        """TC-WEB-13: /attack-lab does not expose real database document UUIDs or recipient names."""
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Secret Executive Diploma",
            recipient_name="Pham Truong Giang",
            doc_type="DIPLOMA",
            file_bytes=b"SECRET_DIPLOMA",
            original_filename="secret.pdf"
        )
        res = self.client.get("/attack-lab")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertNotIn("Pham Truong Giang", html)
        self.assertNotIn(doc["doc_uuid"], html)

    def test_verify_apis_do_not_leak_file_storage_path_or_full_pii(self):
        """TC-WEB-14: Verification APIs (/verify and /api/verify-hash) strip file_storage_path and mask PII for public."""
        doc = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Public Verification Test",
            recipient_name="Hoang Kim Long",
            doc_type="CERTIFICATE",
            file_bytes=b"VERIFY_PAYLOAD_TEST",
            original_filename="verify.pdf"
        )
        # 1. /api/verify-hash
        res_hash = self.client.post("/api/verify-hash", json={"hash": doc["doc_hash"]})
        self.assertEqual(res_hash.status_code, 200)
        data_hash = res_hash.get_json()
        self.assertNotIn("file_storage_path", str(data_hash))
        if data_hash.get("document"):
            self.assertNotIn("Hoang Kim Long", data_hash["document"]["recipient_name"])
            self.assertIn("H*** K*** L***", data_hash["document"]["recipient_name"])

        # 2. /verify (multipart)
        res_file = self.client.post("/verify", data={
            "document_file": (io.BytesIO(b"VERIFY_PAYLOAD_TEST"), "verify.pdf")
        })
        self.assertEqual(res_file.status_code, 200)
        data_file = res_file.get_json()
        self.assertNotIn("file_storage_path", str(data_file))
        if data_file.get("document"):
            self.assertNotIn("Hoang Kim Long", data_file["document"]["recipient_name"])

    def test_simulation_api_rate_limiting(self):
        """TC-WEB-15: CPU-intensive simulation endpoint rate limits callers after 10 requests/minute (HTTP 429)."""
        from src.web.app import _simulation_calls
        _simulation_calls.clear()
        self._login_session("auditor", "AUDITOR")

        # Send 10 calls with valid CSRF
        for _ in range(10):
            res = self.client.post("/api/attack/forge-signature", json={}, headers={"X-CSRFToken": "valid_test_csrf_token_abcdef123456"})
            self.assertEqual(res.status_code, 200)

        # 11th call must return 429 Too Many Requests
        res_11 = self.client.post("/api/attack/forge-signature", json={}, headers={"X-CSRFToken": "valid_test_csrf_token_abcdef123456"})
        self.assertEqual(res_11.status_code, 429)
        self.assertIn("Too Many Requests", res_11.get_json()["error"])

    def test_auditor_incident_response_compromise_issuer(self):
        """TC-WEB-16: Auditor can trigger incident response to lock compromised issuer and batch-revoke documents."""
        doc1 = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Doc 1",
            recipient_name="Student 1",
            doc_type="CERTIFICATE",
            file_bytes=b"DOC_1",
            original_filename="d1.pdf"
        )
        doc2 = self.app.doc_svc.issue_document(
            issuer_id=1,
            title="Doc 2",
            recipient_name="Student 2",
            doc_type="CERTIFICATE",
            file_bytes=b"DOC_2",
            original_filename="d2.pdf"
        )

        # Unauthenticated request (even with CSRF token) fails with HTTP 401
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "valid_test_csrf_token_abcdef123456"
        res_unauth = self.client.post(
            "/api/incident/compromise-issuer",
            json={"issuer_id": 1},
            headers={"X-CSRFToken": "valid_test_csrf_token_abcdef123456"}
        )
        self.assertEqual(res_unauth.status_code, 401)

        # Authenticated as AUDITOR
        self._login_session("auditor", "AUDITOR", user_id=2)
        res = self.client.post(
            "/api/incident/compromise-issuer",
            json={"issuer_id": 1, "reason": "Phát hiện rò rỉ private credentials của phòng đào tạo"},
            headers={"X-CSRFToken": "valid_test_csrf_token_abcdef123456"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "INCIDENT_RESOLVED")
        self.assertEqual(data["account_status"], "COMPROMISED")
        self.assertGreaterEqual(data["revoked_count"], 2)

        # Verify docs are REVOKED
        d1_check = self.app.doc_svc.get_document_by_uuid(doc1["doc_uuid"])
        self.assertEqual(d1_check["status"], "REVOKED")

        # Verify compromised issuer cannot issue new docs
        with self.assertRaises(PermissionError):
            self.app.doc_svc.issue_document(
                issuer_id=1,
                title="Forged",
                recipient_name="Victim",
                doc_type="CERTIFICATE",
                file_bytes=b"NEW",
                original_filename="f.pdf"
            )


if __name__ == "__main__":
    unittest.main()
