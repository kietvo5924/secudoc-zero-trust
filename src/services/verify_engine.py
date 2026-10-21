"""Zero-Trust Verification Engine for Digital Document Authenticity & Integrity."""
from typing import Any
from ..crypto.hashing import calculate_bytes_hash
from ..crypto.keys import KeyManager
from ..crypto.signature import verify_signature, build_canonical_payload, verify_canonical_signature
from ..crypto.merkle import verify_audit_chain
from ..services.doc_service import DocumentService
from ..models.database import DatabaseManager, get_db


class VerificationEngine:
    """
    Zero-Trust Document Verification Pipeline.
    Strictly enforces mathematical verification without assuming client-side or server-side trust:
    1. Raw file bytes SHA-256 hash matching.
    2. Digital signature verification over canonical metadata-bound payload (UUID, doc_hash, recipient, issuer, doc_type, issued_at).
    3. Cross-verification between Document Status, Revocation records, and the Audit Ledger.
    4. Cryptographic integrity of the Audit Hash-Chain.
    """

    def __init__(
        self,
        doc_service: DocumentService | None = None,
        key_manager: KeyManager | None = None,
        db_manager: DatabaseManager | None = None
    ):
        self.db = db_manager or get_db()
        self.key_manager = key_manager or KeyManager()
        self.doc_service = doc_service or DocumentService(self.db, self.key_manager)

    def verify_document(self, file_bytes: bytes, claimed_uuid: str | None = None) -> dict[str, Any]:
        """
        Verify an uploaded document through the complete Zero-Trust pipeline.
        Calculates SHA-256 hash and delegates to verify_hash.
        """
        if not file_bytes:
            return {
                "status": "NOT_FOUND",
                "is_authentic": False,
                "verdict_title": "TỆP RỖNG HOẶC KHÔNG HỢP LỆ",
                "badge_class": "badge-danger",
                "computed_hash": "",
                "expected_hash": None,
                "signature_valid": False,
                "document": None,
                "explanation": "Tệp dữ liệu tải lên rỗng (0 bytes). Vui lòng chọn tệp hợp lệ."
            }

        computed_hash = calculate_bytes_hash(file_bytes)
        return self.verify_hash(computed_hash, claimed_uuid=claimed_uuid)

    def verify_hash(self, computed_hash: str, claimed_uuid: str | None = None) -> dict[str, Any]:
        """
        Verify a document hash directly through the Zero-Trust pipeline.
        Enables Client-Side SHA-256 Hashing (Data Minimization) where sensitive file contents (PII)
        are not uploaded across the network, while the hash/UUID is looked up on the server.
        """
        def _result(status: str, title: str, badge: str, comp_h: str, exp_h: str | None, sig_val: bool, doc_obj: dict | None, expl: str, **kwargs) -> dict[str, Any]:
            res = {
                "status": status,
                "is_authentic": (status == "VERIFIED_AUTHENTIC"),
                "verdict_title": title,
                "badge_class": badge,
                "computed_hash": comp_h,
                "expected_hash": exp_h,
                "signature_valid": sig_val,
                "document": doc_obj,
                "explanation": expl,
            }
            res.update(kwargs)
            return res

        if not computed_hash or len(computed_hash) != 64:
            return _result("NOT_FOUND", "MÃ BĂM RỖNG HOẶC KHÔNG HỢP LỆ", "badge-danger", computed_hash or "", None, False, None, "Mã băm SHA-256 không hợp lệ (phải là chuỗi hex 64 ký tự).")

        computed_hash = computed_hash.lower().strip()
        public_key = self.key_manager.get_public_key()

        # Step 1: Look up document by claimed UUID or by Hash
        if claimed_uuid and claimed_uuid.strip():
            doc = self.doc_service.get_document_by_uuid(claimed_uuid.strip())
            if not doc:
                return _result("NOT_FOUND", "MÃ CHỨNG CHỈ KHÔNG TỒN TẠI", "badge-danger", computed_hash, None, False, None, f"Không tìm thấy tài liệu nào trong hệ thống khớp với mã UUID: {claimed_uuid}.")

            expected_hash = doc["doc_hash"]
            # Check content tampering: does uploaded hash match the issued hash?
            if computed_hash != expected_hash.lower():
                return _result(
                    "TAMPERED_CONTENT",
                    "CẢNH BÁO: VĂN BẢN ĐÃ BỊ CAN THIỆP / SỬA ĐỔI NỘI DUNG!",
                    "badge-danger",
                    computed_hash,
                    expected_hash,
                    False,
                    doc,
                    f"Phát hiện sai lệch mã băm mật mã! Tệp tải lên có mã băm ({computed_hash[:16]}...) "
                    f"hoàn toàn khác biệt với mã băm gốc đã được cơ quan cấp ký phát hành ({expected_hash[:16]}...). "
                    f"Tệp đã bị can thiệp, chỉnh sửa ký tự hoặc làm giả."
                )
        else:
            doc = self.doc_service.get_document_by_hash(computed_hash)
            if not doc:
                return _result(
                    "NOT_FOUND",
                    "TÀI LIỆU CHƯA TỪNG ĐƯỢC PHÁT HÀNH",
                    "badge-warning",
                    computed_hash,
                    None,
                    False,
                    None,
                    f"Mã băm SHA-256 ({computed_hash[:20]}...) của tệp không khớp với bất kỳ văn bản nào "
                    f"trong cơ sở dữ liệu chứng thực. Tài liệu này chưa từng được cấp, hoặc đã bị chỉnh sửa nội dung."
                )
            expected_hash = doc["doc_hash"]

        # Step 2: Verify Digital Signature over Canonical Metadata Payload
        # Binding metadata ensures that tampering with recipient_name, title, doc_type or issuer in SQLite fails verification.
        canonical_payload = build_canonical_payload(
            doc_uuid=doc["doc_uuid"],
            doc_hash=doc["doc_hash"],
            recipient_name=doc["recipient_name"],
            doc_type=doc["doc_type"],
            issuer_name=doc["issuer_name"],
            issued_at=doc["issued_at"],
            version=1
        )
        canonical_valid = verify_canonical_signature(public_key, canonical_payload, doc["signature"])
        # Backwards compatibility fallback: verify raw hash signature for legacy documents
        legacy_valid = verify_signature(public_key, doc["doc_hash"], doc["signature"]) if not canonical_valid else False
        sig_valid = canonical_valid or legacy_valid

        if not sig_valid:
            return _result(
                "INVALID_SIGNATURE",
                "CẢNH BÁO: CHỮ KÝ SỐ HOẶC HỒ SƠ METADATA BỊ CAN THIỆP TRÁI PHÉP!",
                "badge-danger",
                computed_hash,
                expected_hash,
                False,
                doc,
                "Chữ ký số trên văn bản không khớp với dữ liệu hồ sơ (người thụ hưởng, loại tài liệu, mã băm tệp). "
                "Hồ sơ đã bị sửa đổi trái phép trong cơ sở dữ liệu hoặc được ký bởi khóa không hợp pháp."
            )

        # Step 3: Cross-check Revocation Records and Audit Ledger Consistency
        has_revocation_block = False
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM audit_blocks WHERE doc_uuid = ? AND action = 'REVOKE' LIMIT 1;",
                (doc["doc_uuid"],)
            )
            if cursor.fetchone():
                has_revocation_block = True

            cursor.execute(
                "SELECT 1 FROM revocations WHERE doc_uuid = ? LIMIT 1;",
                (doc["doc_uuid"],)
            )
            if cursor.fetchone():
                has_revocation_block = True

        # Conflict Detection: If audit ledger records REVOKE, but document status was tampered to ACTIVE in DB
        if has_revocation_block and doc["status"] != "REVOKED":
            return _result(
                "REVOCATION_CONFLICT",
                "CẢNH BÁO NGUY HIỂM: PHÁT HIỆN GIAN LẬN SỬA ĐỔI TRẠNG THÁI TRONG CSDL!",
                "badge-danger",
                computed_hash,
                expected_hash,
                True,
                doc,
                f"Văn bản '{doc['doc_uuid']}' đã có lệnh THU HỒI chính thức trong Sổ cái kiểm toán, "
                f"nhưng trường trạng thái trong cơ sở dữ liệu đã bị can thiệp trái phép thành '{doc['status']}'. "
                f"Cơ chế Zero-Trust đối chiếu chéo đã phát hiện mâu thuẫn và từ chối công nhận tính hợp lệ!"
            )

        # Step 4: Check Revocation Status
        if doc["status"] == "REVOKED":
            return _result(
                "REVOKED",
                "VĂN BẢN ĐÃ BỊ CƠ QUAN PHÁT HÀNH THU HỒI!",
                "badge-warning",
                computed_hash,
                expected_hash,
                True,
                doc,
                f"Văn bản này từng được phát hành chính thức, nhưng ĐÃ BỊ THU HỒI vào lúc {doc.get('revoked_at')}. "
                f"Lý do thu hồi: {doc.get('revocation_reason')}.",
                revocation_reason=doc.get("revocation_reason", "Thu hồi theo quy định"),
                revoked_at=doc.get("revoked_at")
            )

        # Step 5: Check Audit Chain Integrity
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC;")
            all_blocks = [dict(r) for r in cursor.fetchall()]

        is_chain_valid, broken_idx, broken_reason = verify_audit_chain(all_blocks, require_genesis=True)
        if not is_chain_valid:
            return _result(
                "AUDIT_CHAIN_BROKEN",
                "CẢNH BÁO: TOÀN VẸN SỔ CÁI KIỂM TOÁN HỆ THỐNG ĐÃ BỊ XÂM PHẠM!",
                "badge-danger",
                computed_hash,
                expected_hash,
                True,
                doc,
                f"Phát hiện sự can thiệp trái phép vào Sổ cái kiểm toán hệ thống tại block {broken_idx}: {broken_reason}. "
                f"Hệ thống từ chối chứng thực văn bản khi nền tảng chứng chỉ kiểm toán bị đứt gãy!"
            )

        # Step 6: Full Pass - Verified Authentic
        return _result(
            "VERIFIED_AUTHENTIC",
            "XÁC MINH THÀNH CÔNG: VĂN BẢN NGUYÊN BẢN VÀ CHÍNH GỐC 100%",
            "badge-success",
            computed_hash,
            expected_hash,
            True,
            doc,
            f"Văn bản hoàn toàn toàn vẹn và khớp từng byte với bản gốc do {doc['issuer_name']} ban hành "
            f"vào ngày {doc['issued_at']}. Chữ ký số RSA-2048 và liên kết Sổ cái kiểm toán hoàn toàn hợp lệ."
        )

