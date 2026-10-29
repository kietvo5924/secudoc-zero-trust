"""Flask Web Application for SecuDoc.

Implements Zero-Trust document issuance, verification, audit ledger inspection,
and isolated attack simulation with hardened CSRF, rate-limiting, and open-redirect protections.
"""
import os
import shutil
import secrets
import time
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, send_file
from ..config import (
    BASE_DIR,
    SECRET_KEY,
    MAX_CONTENT_LENGTH,
    KEY_DIR,
    DEMO_MODE,
    DEBUG,
    DATABASE_PATH,
    ATTACK_SANDBOX_DB,
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE
)
from ..crypto.keys import KeyManager
from ..crypto.hashing import calculate_bytes_hash, count_bit_differences, get_bit_difference_vector
from ..crypto.signature import sign_hash, verify_signature
from ..crypto.qr import generate_qr_data_uri
from ..models.database import DatabaseManager, get_db
from ..services.auth_service import AuthService, require_role
from ..services.doc_service import DocumentService, sanitize_filename, mask_recipient_name
from ..services.audit_service import AuditService
from ..services.verify_engine import VerificationEngine
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def is_safe_redirect(target: str | None) -> bool:
    """Validate that the redirect target is a safe relative path, blocking open redirects."""
    if not target:
        return False
    # Reject protocol-relative URLs (//attacker.com), absolute schemes, and backslash bypasses
    if target.startswith("//") or "://" in target or "\\" in target:
        return False
    return target.startswith("/")


def sanitize_verify_result_for_public(result: dict | None, is_authenticated: bool = False) -> dict | None:
    """Sanitize verification result to prevent file_storage_path, raw UUID, and PII leakage."""
    if not result:
        return result
    clean_res = dict(result)
    clean_res.pop("file_storage_path", None)
    if clean_res.get("document"):
        doc = dict(clean_res["document"])
        doc.pop("file_storage_path", None)
        if not is_authenticated:
            if doc.get("recipient_name"):
                doc["recipient_name"] = mask_recipient_name(doc["recipient_name"])
            if doc.get("doc_uuid"):
                raw_u = doc["doc_uuid"]
                doc["doc_uuid"] = raw_u[:8] + "-****-****-****-" + raw_u[-12:]
        clean_res["document"] = doc
    return clean_res


_simulation_calls: dict[str, list[float]] = {}
SIMULATION_RATE_LIMIT_PER_MINUTE = 10


def check_simulation_rate_limit(client_ip: str) -> bool:
    """Enforce strict rate limit on CPU-intensive simulation endpoints (e.g. RSA key generation)."""
    now = time.time()
    calls = _simulation_calls.get(client_ip, [])
    calls = [t for t in calls if now - t < 60.0]
    _simulation_calls[client_ip] = calls
    if len(calls) >= SIMULATION_RATE_LIMIT_PER_MINUTE:
        return False
    calls.append(now)
    return True


def create_app(test_config=None) -> Flask:
    """Create and configure the Flask Application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["SESSION_COOKIE_HTTPONLY"] = SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
    app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
    app.config["DEMO_MODE"] = DEMO_MODE
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    if test_config:
        app.config.update(test_config)

    db_path = app.config.get("DATABASE_PATH", DATABASE_PATH)
    sandbox_db_path = app.config.get("ATTACK_SANDBOX_DB", ATTACK_SANDBOX_DB)

    db_mgr = DatabaseManager(db_path)
    sandbox_db_mgr = DatabaseManager(sandbox_db_path)

    key_mgr = KeyManager()
    auth_svc = AuthService(db_mgr)
    doc_svc = DocumentService(db_mgr, key_mgr)
    audit_svc = AuditService(db_mgr)
    sandbox_audit_svc = AuditService(sandbox_db_mgr)
    verify_engine = VerificationEngine(doc_svc, key_mgr, db_mgr)

    app.db_mgr = db_mgr
    app.sandbox_db_mgr = sandbox_db_mgr
    app.key_mgr = key_mgr
    app.auth_svc = auth_svc
    app.doc_svc = doc_svc
    app.audit_svc = audit_svc
    app.sandbox_audit_svc = sandbox_audit_svc
    app.verify_engine = verify_engine

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:;"
        )
        return response

    def get_or_create_csrf_token() -> str:
        """Retrieve existing CSRF token from session or generate a cryptographically random one."""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    @app.context_processor
    def inject_context():
        return {
            "current_user": session.get("user"),
            "csrf_token": get_or_create_csrf_token,
            "demo_mode": app.config.get("DEMO_MODE", False),
        }

    # CSRF Protection Middleware for state-changing HTTP requests
    @app.before_request
    def enforce_csrf():
        # Ensure session has a token for forms
        get_or_create_csrf_token()

        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # Exclude state-free verification APIs from CSRF
            if request.path in ("/verify", "/api/verify-hash"):
                return None

            # Skip CSRF check only if disabled in test config
            if app.config.get("WTF_CSRF_ENABLED") is False or app.config.get("TESTING_CSRF_DISABLED"):
                return None

            submitted_token = (
                request.headers.get("X-CSRFToken")
                or request.headers.get("X-CSRF-Token")
                or request.form.get("csrf_token")
            )
            expected_token = session.get("csrf_token")

            if not expected_token or not submitted_token or not secrets.compare_digest(submitted_token, expected_token):
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": "Bad Request", "message": "CSRF token missing or invalid"}), 400
                flash("Lỗi bảo mật: CSRF token không hợp lệ hoặc phiên làm việc đã hết hạn.", "danger")
                return redirect(request.referrer or url_for("index"))

    # ---------------------------------------------------------
    # Public Routes
    # ---------------------------------------------------------
    @app.route("/", methods=["GET", "POST"])
    def index():
        result = None
        is_authed = bool(session.get("user"))
        if request.method == "POST":
            uploaded_file = request.files.get("document_file")
            raw_uuid = request.form.get("claimed_uuid") or ""
            claimed_uuid = str(raw_uuid).strip() if raw_uuid and str(raw_uuid).strip() else None

            if not uploaded_file or uploaded_file.filename == "":
                flash("Vui lòng chọn tệp văn bản cần xác minh", "danger")
            else:
                file_bytes = uploaded_file.read()
                raw_result = verify_engine.verify_document(file_bytes, claimed_uuid=claimed_uuid)
                result = sanitize_verify_result_for_public(raw_result, is_authenticated=is_authed)

        # Apply Data Minimization: Mask recipient PII and internal UUID on public landing page
        raw_recent = doc_svc.list_documents(limit=5)
        recent_docs = []
        for d in raw_recent:
            masked_doc = dict(d)
            masked_doc.pop("file_storage_path", None)
            if not is_authed:
                masked_doc["recipient_name"] = mask_recipient_name(d["recipient_name"])
                raw_u = d["doc_uuid"]
                masked_doc["doc_uuid"] = raw_u[:8] + "-****-****-****-" + raw_u[-12:]
            recent_docs.append(masked_doc)

        return render_template("index.html", result=result, recent_docs=recent_docs)

    @app.route("/verify", methods=["POST"])
    def verify_api():
        uploaded_file = request.files.get("document_file")
        raw_uuid = request.form.get("claimed_uuid") or ""
        claimed_uuid = str(raw_uuid).strip() if raw_uuid and str(raw_uuid).strip() else None

        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"error": "No file provided"}), 400

        file_bytes = uploaded_file.read()
        raw_result = verify_engine.verify_document(file_bytes, claimed_uuid=claimed_uuid)
        is_authed = bool(session.get("user"))
        return jsonify(sanitize_verify_result_for_public(raw_result, is_authenticated=is_authed))

    @app.route("/api/verify-hash", methods=["POST"])
    def api_verify_hash():
        """
        Verify a document SHA-256 hash calculated in-browser (Client-side Hashing / Data Minimization).
        The raw bytes of sensitive files are not uploaded, but the hash/UUID is looked up on the server.
        """
        data = request.get_json(silent=True) or {}
        raw_hash = data.get("hash") or data.get("doc_hash") or ""
        hash_val = str(raw_hash).strip()
        raw_uuid = data.get("claimed_uuid") or data.get("uuid")
        claimed_uuid = str(raw_uuid).strip() if raw_uuid and str(raw_uuid).strip() else None

        if not hash_val:
            return jsonify({"error": "No hash provided"}), 400

        raw_result = verify_engine.verify_hash(hash_val, claimed_uuid=claimed_uuid)
        is_authed = bool(session.get("user"))
        return jsonify(sanitize_verify_result_for_public(raw_result, is_authenticated=is_authed))

    @app.route("/api/public-key", methods=["GET"])
    def get_public_key():
        """Export Root Public Key and fingerprint for local trust verification."""
        pem_str = key_mgr.get_public_key_pem()
        fingerprint = key_mgr.get_public_key_fingerprint()
        return jsonify({
            "key_type": "RSA-2048",
            "format": "SubjectPublicKeyInfo PEM",
            "sha256_fingerprint": fingerprint,
            "public_key_pem": pem_str,
            "trust_model": "Local University Root Key (Prototype Demo)"
        })

    @app.route("/api/trust-info", methods=["GET"])
    def get_trust_info():
        """Provide detailed information on the local trust boundary and root keys."""
        return jsonify({
            "system_name": "SecuDoc Zero-Trust Verification Prototype",
            "academic_course": "Bảo mật mạng máy tính và hệ thống",
            "key_fingerprint": key_mgr.get_public_key_fingerprint(),
            "root_public_key_fingerprint": key_mgr.get_public_key_fingerprint(),
            "trust_model": "Local University Root Key (Prototype Demo)",
            "algorithm": "RSA-2048 with PKCS#1 v1.5 and SHA-256",
            "ledger_type": "Cryptographic Hash-Chain (Linear Block-Linked)",
            "limitations": [
                "Prototype utilizes local root key pair, not an accredited public PKI/CA.",
                "Storage is hosted on local SQLite; database security relies on host OS access control.",
                "Client-side hashing preserves bandwidth and file privacy, but is not a Zero-Knowledge Proof."
            ]
        })

    @app.route("/api/sample/<filename>", methods=["GET"])
    def get_sample_file(filename):
        """Serve sample files for quick demonstration in browser."""
        safe_name = sanitize_filename(filename)
        sample_path = BASE_DIR / "samples" / safe_name
        if not sample_path.is_file():
            abort(404)
        return send_file(sample_path, as_attachment=False)

    # ---------------------------------------------------------
    # Authentication Routes
    # ---------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user"):
            user_role = session["user"]["role"]
            if user_role == "ISSUER":
                return redirect(url_for("dashboard"))
            elif user_role == "AUDITOR":
                return redirect(url_for("audit_page"))
            return redirect(url_for("index"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            client_ip = request.remote_addr or "127.0.0.1"

            try:
                user = auth_svc.authenticate(username, password, client_ip=client_ip)
            except PermissionError as e:
                flash(str(e), "danger")
                return render_template("login.html"), 429

            if user:
                session.clear()
                session["user"] = user
                session["csrf_token"] = secrets.token_hex(32)
                flash(f"Đăng nhập thành công! Chào mừng {user['full_name']}", "success")

                next_url = request.args.get("next") or request.form.get("next")
                if is_safe_redirect(next_url):
                    return redirect(next_url)

                if user["role"] == "ISSUER":
                    return redirect(url_for("dashboard"))
                elif user["role"] == "AUDITOR":
                    return redirect(url_for("audit_page"))
                return redirect(url_for("index"))
            else:
                flash("Tên đăng nhập hoặc mật khẩu không chính xác!", "danger")

        return render_template("login.html")

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        session.clear()
        flash("Đã đăng xuất an toàn khỏi hệ thống", "info")
        return redirect(url_for("index"))

    # ---------------------------------------------------------
    # Issuer Dashboard Routes
    # ---------------------------------------------------------
    @app.route("/dashboard")
    @require_role("ISSUER")
    def dashboard():
        user = session["user"]
        documents = doc_svc.list_documents(issuer_id=user["id"], limit=50)
        return render_template("dashboard.html", documents=documents)

    @app.route("/issue", methods=["POST"])
    @require_role("ISSUER")
    def issue_document():
        user = session["user"]
        title = request.form.get("title", "").strip()
        recipient_name = request.form.get("recipient_name", "").strip()
        doc_type = request.form.get("doc_type", "CERTIFICATE").strip()
        uploaded_file = request.files.get("document_file")

        if not title or not recipient_name or not uploaded_file or uploaded_file.filename == "":
            flash("Vui lòng điền đầy đủ thông tin và chọn tệp đính kèm", "warning")
            return redirect(url_for("dashboard"))

        try:
            file_bytes = uploaded_file.read()
            doc = doc_svc.issue_document(
                issuer_id=user["id"],
                title=title,
                recipient_name=recipient_name,
                doc_type=doc_type,
                file_bytes=file_bytes,
                original_filename=uploaded_file.filename
            )
            flash(f"Phát hành và ký số văn bản thành công! Mã chứng nhận: {doc['doc_uuid']}", "success")
        except PermissionError as e:
            flash(f"Từ chối phát hành văn bản: {str(e)}", "danger")
        except ValueError as e:
            flash(f"Lỗi kiểm tra tệp đầu vào: {str(e)}", "warning")
        except Exception as e:
            flash(f"Lỗi khi phát hành văn bản: {str(e)}", "danger")

        return redirect(url_for("dashboard"))

    @app.route("/revoke/<doc_uuid>", methods=["POST"])
    @require_role("ISSUER")
    def revoke_document(doc_uuid):
        user = session["user"]
        reason = request.form.get("reason", "Thu hồi theo quy định của cơ quan phát hành").strip()
        try:
            doc_svc.revoke_document(doc_uuid, revoked_by=user["id"], reason=reason)
            flash(f"Đã thu hồi thành công văn bản UUID: {doc_uuid}", "warning")
        except Exception as e:
            flash(f"Lỗi khi thu hồi văn bản: {str(e)}", "danger")

        return redirect(url_for("dashboard"))

    # ---------------------------------------------------------
    # Auditor Ledger & Incident Response Routes
    # ---------------------------------------------------------
    @app.route("/audit")
    @require_role("AUDITOR")
    def audit_page():
        blocks = audit_svc.get_all_audit_blocks()
        verification_status = audit_svc.verify_chain_integrity(require_genesis=True)
        return render_template("audit.html", blocks=blocks, verification=verification_status)

    @app.route("/api/audit/verify", methods=["GET"])
    @require_role("AUDITOR")
    def api_verify_audit():
        status = audit_svc.verify_chain_integrity(require_genesis=True)
        return jsonify(status)

    @app.route("/api/incident/compromise-issuer", methods=["POST"])
    @require_role("AUDITOR")
    def api_incident_compromise_issuer():
        """
        Incident Response: When an Issuer account is compromised, lock the account and batch-revoke all issued documents.
        Strictly restricted to AUDITOR role.
        """
        data = request.get_json(silent=True) or {}
        issuer_id = data.get("issuer_id")
        reason = data.get("reason", "Tài khoản Issuer bị lộ thông tin xác thực / xâm nhập trái phép").strip()

        if not issuer_id:
            return jsonify({"error": "Bad Request", "message": "Thiếu issuer_id"}), 400

        try:
            issuer_id = int(issuer_id)
        except ValueError:
            return jsonify({"error": "Bad Request", "message": "issuer_id phải là số nguyên"}), 400

        auditor_user = session["user"]
        revoked_uuids = doc_svc.emergency_batch_revoke(
            issuer_id=issuer_id,
            reason=reason,
            revoked_by=auditor_user["id"]
        )

        return jsonify({
            "status": "INCIDENT_RESOLVED",
            "issuer_id": issuer_id,
            "account_status": "COMPROMISED",
            "revoked_count": len(revoked_uuids),
            "revoked_uuids": revoked_uuids,
            "message": f"Đã khóa tài khoản Issuer (ID {issuer_id}) và thu hồi khẩn cấp {len(revoked_uuids)} văn bản."
        })

    # ---------------------------------------------------------
    # Attack Lab Simulator Routes (Isolated Sandbox)
    # ---------------------------------------------------------
    @app.route("/attack-lab")
    def attack_lab():
        # Do not expose real database documents or recipient names to unauthenticated attack lab
        return render_template("attack_demo.html")

    @app.route("/api/attack/bit-flip", methods=["POST"])
    def api_attack_bit_flip():
        """
        Simulate a Bit-Flip Tampering Attack:
        Operates strictly on isolated synthetic sample data to prevent raw document leakage.
        """
        client_ip = request.remote_addr or "127.0.0.1"
        if not check_simulation_rate_limit(client_ip):
            return jsonify({
                "error": "Too Many Requests",
                "message": "Giới hạn tần suất gọi API mô phỏng tốn CPU (Rate limit: 10 lần/phút). Vui lòng thử lại sau."
            }), 429

        data = request.get_json(silent=True) or {}
        sample_choice = data.get("sample_type") or data.get("doc_uuid") or ""

        if sample_choice == "SAMPLE_TRANSCRIPT":
            original_bytes = (
                b"TRUONG DAI HOC - BANG DIEM CHINH THUC GIA LAP\n"
                b"Sinh vien: NGUYEN VAN B - Diem GPA: 3.85 - Xep loai: GIOI\n"
            )
        elif sample_choice == "SAMPLE_CERTIFICATE":
            original_bytes = (
                b"TRUONG DAI HOC - CHUNG CHI HOAN THANH KHOA HOC GIA LAP\n"
                b"Hoc vien: TRAN THI C - Xep loai: XUAT SAC\n"
            )
        else:
            original_bytes = (
                b"TRUONG DAI HOC CONG NGHE THONG TIN - BANG TOT NGHIEP GIA LAP\n"
                b"Sinh vien: NGUYEN VAN A - Xep loai: XUAT SAC - Diem GPA: 3.90\n"
            )
        original_hash = calculate_bytes_hash(original_bytes)

        # Flip the least significant bit of the first byte
        byte_array = bytearray(original_bytes)
        if len(byte_array) > 0:
            byte_array[0] ^= 0x01
        tampered_bytes = bytes(byte_array)
        tampered_hash = calculate_bytes_hash(tampered_bytes)

        diff_bits, total_bits, pct = count_bit_differences(original_hash, tampered_hash)
        bit_vector = get_bit_difference_vector(original_hash, tampered_hash)

        orig_byte_val = original_bytes[0] if len(original_bytes) > 0 else 0
        tamp_byte_val = tampered_bytes[0] if len(tampered_bytes) > 0 else 0
        orig_char = chr(orig_byte_val) if 32 <= orig_byte_val <= 126 else f"\\x{orig_byte_val:02x}"
        tamp_char = chr(tamp_byte_val) if 32 <= tamp_byte_val <= 126 else f"\\x{tamp_byte_val:02x}"

        # Run through verification engine
        verdict = verify_engine.verify_document(tampered_bytes)
        safe_verdict = sanitize_verify_result_for_public(verdict, is_authenticated=bool(session.get("user")))

        return jsonify({
            "original_hash": original_hash,
            "tampered_hash": tampered_hash,
            "diff_bits": diff_bits,
            "total_bits": total_bits,
            "avalanche_percentage": round(pct, 2),
            "bit_vector": bit_vector,
            "byte_offset": 0,
            "original_byte_hex": f"0x{orig_byte_val:02X}",
            "original_byte_bin": f"{orig_byte_val:08b}",
            "original_char": orig_char,
            "tampered_byte_hex": f"0x{tamp_byte_val:02X}",
            "tampered_byte_bin": f"{tamp_byte_val:08b}",
            "tampered_char": tamp_char,
            "verdict": safe_verdict
        })

    @app.route("/api/attack/forge-signature", methods=["POST"])
    def api_attack_forge_signature():
        """
        Simulate Signature Forgery:
        An attacker generates their own rogue RSA keypair and attempts to sign a legitimate document.
        Rate limited to protect CPU against repetitive 2048-bit RSA key generation.
        """
        client_ip = request.remote_addr or "127.0.0.1"
        if not check_simulation_rate_limit(client_ip):
            return jsonify({
                "error": "Too Many Requests",
                "message": "Giới hạn tần suất gọi API mô phỏng tốn CPU (Rate limit: 10 lần/phút). Vui lòng thử lại sau."
            }), 429

        data = request.get_json(silent=True) or {}
        target_hash = calculate_bytes_hash(b"SAMPLE_DATA_FOR_SIMULATION")

        # Rogue attacker generates a separate RSA keypair
        fake_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        forged_signature = sign_hash(fake_private_key, target_hash)

        # Check with official public key
        official_public_key = key_mgr.get_public_key()
        is_valid_against_root = verify_signature(official_public_key, target_hash, forged_signature)

        return jsonify({
            "target_hash": target_hash,
            "forged_signature": forged_signature[:64] + "...",
            "official_root_verification": is_valid_against_root,
            "blocked": not is_valid_against_root,
            "explanation": "Chữ ký giả mạo tạo bởi khóa riêng của kẻ tấn công đã bị Khóa công khai của trường từ chối 100%!"
        })

    @app.route("/api/attack/tamper-db", methods=["POST"])
    @require_role("AUDITOR")
    def api_attack_tamper_db():
        """
        Simulate malicious insider editing an audit record in the ISOLATED SANDBOX database.
        Strictly prohibited outside DEMO_MODE; never mutates the primary runtime database.
        """
        if not app.config.get("DEMO_MODE"):
            return jsonify({"error": "Forbidden", "message": "Database mutation simulations are disabled outside DEMO_MODE"}), 403

        data = request.get_json() or {}
        block_idx = int(data.get("block_index", 0))
        field_to_alter = data.get("field", "action")
        malicious_value = data.get("malicious_value", "HACKED_ACTION")

        # Mutate strictly in the isolated sandbox database
        success = sandbox_audit_svc.simulate_database_tamper(
            block_idx,
            field_to_alter=field_to_alter,
            malicious_value=malicious_value
        )
        verification = sandbox_audit_svc.verify_chain_integrity(require_genesis=True)

        return jsonify({
            "tamper_executed": success,
            "tampered_block": block_idx,
            "target_database": "attack_sandbox.db (ISOLATED)",
            "verification": verification
        })

    @app.route("/api/attack/restore-db", methods=["POST"])
    @require_role("AUDITOR")
    def api_attack_restore_db():
        """
        Restore tampered block in the ISOLATED SANDBOX database back to authentic state.
        Restores any block index using recorded snapshots.
        """
        if not app.config.get("DEMO_MODE"):
            return jsonify({"error": "Forbidden", "message": "Database mutation simulations are disabled outside DEMO_MODE"}), 403

        data = request.get_json() or {}
        block_idx = int(data.get("block_index", 0))

        success = sandbox_audit_svc.restore_database_block(block_idx)
        verification = sandbox_audit_svc.verify_chain_integrity(require_genesis=True)

        return jsonify({
            "restore_executed": success,
            "restored_block": block_idx,
            "target_database": "attack_sandbox.db (ISOLATED)",
            "verification": verification
        })

    @app.route("/certificate/<doc_uuid>")
    def view_certificate(doc_uuid):
        """Display an official verifiable digital credential with PII protection."""
        doc = doc_svc.get_document_by_uuid(doc_uuid)
        if not doc:
            flash("Không tìm thấy hồ sơ văn bản tương ứng", "danger")
            return redirect(url_for("index"))

        user = session.get("user")
        is_authorized = bool(user and (user.get("role") in ("ISSUER", "AUDITOR") or user.get("id") == doc["issuer_id"]))

        # Data Minimization: If visitor is not an authorized issuer/auditor, mask recipient PII and redact internal UUID
        display_doc = dict(doc)
        display_doc.pop("file_storage_path", None)
        if not is_authorized:
            display_doc["recipient_name"] = mask_recipient_name(doc["recipient_name"])
            raw_u = doc["doc_uuid"]
            display_doc["doc_uuid"] = raw_u[:8] + "-****-****-****-" + raw_u[-12:]

        public_key_pem = key_mgr.get_public_key_pem()
        root_fingerprint = key_mgr.get_public_key_fingerprint()

        # Build absolute verification URL for QR code
        verify_url = request.url_root.rstrip("/") + "/?uuid=" + doc["doc_uuid"]
        qr_data_uri = generate_qr_data_uri(verify_url)

        return render_template(
            "certificate.html",
            doc=display_doc,
            public_key_pem=public_key_pem,
            root_fingerprint=root_fingerprint,
            verify_url=verify_url,
            qr_data_uri=qr_data_uri,
            is_authorized=is_authorized
        )

    @app.route("/download/<doc_uuid>")
    def download_document(doc_uuid):
        """Allow downloading the authentic binary document file ONLY for authenticated authorized users."""
        user = session.get("user")
        if not user:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "Yêu cầu đăng nhập để tải tài liệu"}), 401
            flash("Vui lòng đăng nhập để tải tài liệu gốc.", "warning")
            return redirect(url_for("login", next=request.path))

        doc = doc_svc.get_document_by_uuid(doc_uuid)
        if not doc:
            abort(404)

        # Authorization check: only the issuing user or an AUDITOR can download the raw file
        if user.get("role") not in ("ISSUER", "AUDITOR") or (user.get("role") == "ISSUER" and doc["issuer_id"] != user["id"]):
            abort(403)

        file_path = Path(doc["file_storage_path"])
        if not file_path.is_file():
            abort(404)
        return send_file(file_path, as_attachment=True, download_name=doc["original_filename"])

    return app

    return app

