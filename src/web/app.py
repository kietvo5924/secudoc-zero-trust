"""Flask Web Application for SecuDoc."""
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from ..config import SECRET_KEY, MAX_CONTENT_LENGTH, KEY_DIR
from ..crypto.keys import KeyManager
from ..crypto.hashing import calculate_bytes_hash, count_bit_differences, get_bit_difference_vector
from ..crypto.signature import sign_hash
from ..models.database import DatabaseManager, get_db
from ..services.auth_service import AuthService, require_role
from ..services.doc_service import DocumentService
from ..services.audit_service import AuditService
from ..services.verify_engine import VerificationEngine
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def create_app(test_config=None) -> Flask:
    """Create and configure the Flask Application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    if test_config:
        app.config.update(test_config)

    db_path = app.config.get("DATABASE_PATH")
    db_mgr = DatabaseManager(db_path) if db_path else get_db()
    key_mgr = KeyManager()
    auth_svc = AuthService(db_mgr)
    doc_svc = DocumentService(db_mgr, key_mgr)
    audit_svc = AuditService(db_mgr)
    verify_engine = VerificationEngine(doc_svc, key_mgr, db_mgr)

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

    @app.context_processor
    def inject_user():
        return {"current_user": session.get("user")}

    # ---------------------------------------------------------
    # Public Routes
    # ---------------------------------------------------------
    @app.route("/", methods=["GET", "POST"])
    def index():
        result = None
        if request.method == "POST":
            uploaded_file = request.files.get("document_file")
            claimed_uuid = request.form.get("claimed_uuid", "").strip()

            if not uploaded_file or uploaded_file.filename == "":
                flash("Vui lòng chọn tệp văn bản cần xác minh", "danger")
            else:
                file_bytes = uploaded_file.read()
                result = verify_engine.verify_document(file_bytes, claimed_uuid=claimed_uuid or None)

        recent_docs = doc_svc.list_documents(limit=5)
        return render_template("index.html", result=result, recent_docs=recent_docs)

    @app.route("/verify", methods=["POST"])
    def verify_api():
        uploaded_file = request.files.get("document_file")
        claimed_uuid = request.form.get("claimed_uuid", "").strip()

        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"error": "No file provided"}), 400

        file_bytes = uploaded_file.read()
        result = verify_engine.verify_document(file_bytes, claimed_uuid=claimed_uuid or None)
        return jsonify(result)

    @app.route("/api/verify-hash", methods=["POST"])
    def api_verify_hash():
        """
        Verify a document SHA-256 hash calculated in-browser (Web Crypto API).
        Preserves client privacy by never uploading sensitive file bytes (PII) to the server.
        Directly fulfills Personal Privacy / GDPR / Decree 13 requirements.
        """
        data = request.get_json() or {}
        hash_val = data.get("hash", "").strip()
        claimed_uuid = data.get("claimed_uuid", "").strip() or None

        if not hash_val:
            return jsonify({"error": "No hash provided"}), 400

        result = verify_engine.verify_hash(hash_val, claimed_uuid=claimed_uuid)
        return jsonify(result)

    @app.route("/api/public-key", methods=["GET"])
    def get_public_key():
        """Export Root Public Key for independent offline verification."""
        pem_str = key_mgr.get_public_key_pem()
        return jsonify({
            "key_type": "RSA-2048",
            "format": "SubjectPublicKeyInfo PEM",
            "public_key_pem": pem_str
        })

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

            user = auth_svc.authenticate(username, password)
            if user:
                session.clear()
                session["user"] = user
                flash(f"Đăng nhập thành công! Chào mừng {user['full_name']}", "success")
                next_url = request.args.get("next")
                if next_url and next_url.startswith("/"):
                    return redirect(next_url)
                if user["role"] == "ISSUER":
                    return redirect(url_for("dashboard"))
                elif user["role"] == "AUDITOR":
                    return redirect(url_for("audit_page"))
                return redirect(url_for("index"))
            else:
                flash("Tên đăng nhập hoặc mật khẩu không chính xác!", "danger")

        return render_template("login.html")

    @app.route("/logout")
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
    # Auditor Ledger Routes
    # ---------------------------------------------------------
    @app.route("/audit")
    @require_role("AUDITOR")
    def audit_page():
        blocks = audit_svc.get_all_audit_blocks()
        verification_status = audit_svc.verify_chain_integrity()
        return render_template("audit.html", blocks=blocks, verification=verification_status)

    @app.route("/api/audit/verify", methods=["GET"])
    @require_role("AUDITOR")
    def api_verify_audit():
        status = audit_svc.verify_chain_integrity()
        return jsonify(status)

    # ---------------------------------------------------------
    # Attack Lab Simulator Routes (For Live Demo)
    # ---------------------------------------------------------
    @app.route("/attack-lab")
    def attack_lab():
        recent_docs = doc_svc.list_documents(limit=10)
        return render_template("attack_demo.html", recent_docs=recent_docs)

    @app.route("/api/attack/bit-flip", methods=["POST"])
    def api_attack_bit_flip():
        """
        Simulate a Bit-Flip Tampering Attack:
        Take a document, flip 1 byte, compute hashes, calculate Hamming distance,
        and run verification through Zero-Trust engine.
        """
        data = request.get_json() or {}
        doc_uuid = data.get("doc_uuid")
        doc = doc_svc.get_document_by_uuid(doc_uuid) if doc_uuid else None

        if not doc:
            # Fallback to demo sample text
            original_bytes = (
                b"TRUONG DAI HOC CONG NGHE THONG TIN - BANG TOT NGHIEP\n"
                b"Sinh vien: NGUYEN VAN A - Xep loai: XUAT SAC - Diem GPA: 3.90\n"
            )
            original_hash = calculate_bytes_hash(original_bytes)
        else:
            storage_path = doc["file_storage_path"]
            if os.path.exists(storage_path):
                with open(storage_path, "rb") as f:
                    original_bytes = f.read()
            else:
                original_bytes = f"Văn bản {doc['title']} của {doc['recipient_name']}".encode("utf-8")
            original_hash = doc["doc_hash"]

        # Flip the first byte
        byte_array = bytearray(original_bytes)
        if len(byte_array) > 0:
            byte_array[0] ^= 0x01  # Flip least significant bit of first byte
        tampered_bytes = bytes(byte_array)
        tampered_hash = calculate_bytes_hash(tampered_bytes)

        diff_bits, total_bits, pct = count_bit_differences(original_hash, tampered_hash)
        bit_vector = get_bit_difference_vector(original_hash, tampered_hash)

        # Forensic details of the modification
        orig_byte_val = original_bytes[0] if len(original_bytes) > 0 else 0
        tamp_byte_val = tampered_bytes[0] if len(tampered_bytes) > 0 else 0
        orig_char = chr(orig_byte_val) if 32 <= orig_byte_val <= 126 else f"\\x{orig_byte_val:02x}"
        tamp_char = chr(tamp_byte_val) if 32 <= tamp_byte_val <= 126 else f"\\x{tamp_byte_val:02x}"

        # Run through verification engine
        verdict = verify_engine.verify_document(tampered_bytes, claimed_uuid=doc_uuid if doc else None)

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
            "verdict": verdict
        })

    @app.route("/api/attack/forge-signature", methods=["POST"])
    def api_attack_forge_signature():
        """
        Simulate Signature Forgery:
        An attacker generates their own rogue RSA keypair and attempts to sign a legitimate document.
        """
        data = request.get_json() or {}
        doc_uuid = data.get("doc_uuid")
        doc = doc_svc.get_document_by_uuid(doc_uuid) if doc_uuid else None

        target_hash = doc["doc_hash"] if doc else calculate_bytes_hash(b"SAMPLE_DATA")

        # Rogue attacker generates a new RSA keypair
        fake_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        forged_signature = sign_hash(fake_private_key, target_hash)

        # Check with official public key
        official_public_key = key_mgr.get_public_key()
        from ..crypto.signature import verify_signature
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
        """Simulate malicious insider editing a database record directly."""
        data = request.get_json() or {}
        block_idx = int(data.get("block_index", 0))
        success = audit_svc.simulate_database_tamper(block_idx, field_to_alter="action", malicious_value="HACKED_ACTION")
        verification = audit_svc.verify_chain_integrity()
        return jsonify({
            "tamper_executed": success,
            "tampered_block": block_idx,
            "verification": verification
        })

    @app.route("/api/attack/restore-db", methods=["POST"])
    @require_role("AUDITOR")
    def api_attack_restore_db():
        """Restore database tamper back to authentic state for repeatable live demonstrations."""
        data = request.get_json() or {}
        block_idx = int(data.get("block_index", 0))
        success = audit_svc.restore_database_block(block_idx, field_to_restore="action", original_value="GENESIS")
        verification = audit_svc.verify_chain_integrity()
        return jsonify({
            "restore_executed": success,
            "restored_block": block_idx,
            "verification": verification
        })

    @app.route("/certificate/<doc_uuid>")
    def view_certificate(doc_uuid):
        """Display an official verifiable digital credential with QR code and cryptographic proof."""
        doc = doc_svc.get_document_by_uuid(doc_uuid)
        if not doc:
            flash("Không tìm thấy hồ sơ văn bản tương ứng", "danger")
            return redirect(url_for("index"))
        public_key_pem = key_mgr.get_public_key_pem()
        return render_template("certificate.html", doc=doc, public_key_pem=public_key_pem)

    return app
