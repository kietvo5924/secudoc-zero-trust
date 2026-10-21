"""Zero-Trust Verification Engine for Digital Document Authenticity & Integrity."""
from typing import Any
from ..crypto.hashing import calculate_bytes_hash
from ..crypto.keys import KeyManager
from ..crypto.signature import verify_signature
from ..services.doc_service import DocumentService
from ..models.database import DatabaseManager, get_db


class VerificationEngine:
    """
    Zero-Trust Document Verification Pipeline.
    Strictly enforces mathematical verification without assuming client-side trust.
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
        Calculates SHA-256 hash in streaming mode and delegates to verify_hash.
        """
        if not file_bytes:
            return {
                "status": "NOT_FOUND",
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
        Enables Privacy-Preserving In-Browser Verification (Web Crypto API) where
        sensitive file contents (PII) are never transmitted across the network.
        """
        if not computed_hash or len(computed_hash) != 64:
            return {
                "status": "NOT_FOUND",
                "verdict_title": "MÃ BĂM RỖNG HOẶC KHÔNG HỢP LỆ",
                "badge_class": "badge-danger",
                "computed_hash": computed_hash or "",
                "expected_hash": None,
                "signature_valid": False,
                "document": None,
                "explanation": "Mã băm SHA-256 không hợp lệ (phải là chuỗi hex 64 ký tự)."
            }

        computed_hash = computed_hash.lower().strip()
        public_key = self.key_manager.get_public_key()

        # Case A: User provided a claimed UUID (e.g. from a QR code or student submission ID)
        if claimed_uuid and claimed_uuid.strip():
            doc = self.doc_service.get_document_by_uuid(claimed_uuid.strip())
            if not doc:
                return {
                    "status": "NOT_FOUND",
                    "verdict_title": "MÃ CHỨNG CHỈ KHÔNG TỒN TẠI",
                    "badge_class": "badge-danger",
                    "computed_hash": computed_hash,
                    "expected_hash": None,
                    "signature_valid": False,
                    "document": None,
                    "explanation": f"Không tìm thấy tài liệu nào trong hệ thống khớp với mã UUID: {claimed_uuid}."
                }

            expected_hash = doc["doc_hash"]
            # Check content tampering: does uploaded hash match the issued hash?
            if computed_hash != expected_hash.lower():
                return {
                    "status": "TAMPERED_CONTENT",
                    "verdict_title": "CẢNH BÁO: VĂN BẢN ĐÃ BỊ CAN THIỆP / SỬA ĐỔI NỘI DUNG!",
                    "badge_class": "badge-danger",
                    "computed_hash": computed_hash,
                    "expected_hash": expected_hash,
                    "signature_valid": False,
                    "document": doc,
                    "explanation": (
                        f"Phát hiện sai lệch mã băm mật mã! Tệp tải lên có mã băm ({computed_hash[:16]}...) "
                        f"hoàn toàn khác biệt với mã băm gốc đã được cơ quan cấp ký phát hành ({expected_hash[:16]}...). "
                        f"Tệp đã bị can thiệp, chỉnh sửa ký tự hoặc làm giả."
                    )
                }

        # Case B: No UUID provided, look up solely by calculated SHA-256 hash
        else:
            doc = self.doc_service.get_document_by_hash(computed_hash)
            if not doc:
                return {
                    "status": "NOT_FOUND",
                    "verdict_title": "TÀI LIỆU CHƯA TỪNG ĐƯỢC PHÁT HÀNH",
                    "badge_class": "badge-warning",
                    "computed_hash": computed_hash,
                    "expected_hash": None,
                    "signature_valid": False,
                    "document": None,
                    "explanation": (
                        f"Mã băm SHA-256 ({computed_hash[:20]}...) của tệp không khớp với bất kỳ văn bản nào "
                        f"trong cơ sở dữ liệu chứng thực. Tài liệu này chưa từng được cấp, hoặc đã bị chỉnh sửa nội dung."
                    )
                }
            expected_hash = doc["doc_hash"]

        # Step 4: Verify Digital Signature using Issuer Root Public Key
        sig_valid = verify_signature(public_key, doc["doc_hash"], doc["signature"])
        if not sig_valid:
            return {
                "status": "INVALID_SIGNATURE",
                "verdict_title": "CẢNH BÁO: CHỮ KÝ SỐ KHÔNG HỢP LỆ HOẶC BỊ LÀM GIẢ!",
                "badge_class": "badge-danger",
                "computed_hash": computed_hash,
                "expected_hash": expected_hash,
                "signature_valid": False,
                "document": doc,
                "explanation": (
                    "Chữ ký số trên văn bản không được tạo ra bởi Khóa riêng của Cơ quan phát hành hợp pháp, "
                    "hoặc chữ ký số đã bị sửa đổi trái phép."
                )
            }

        # Step 5: Check Revocation Status
        if doc["status"] == "REVOKED":
            return {
                "status": "REVOKED",
                "verdict_title": "VĂN BẢN ĐÃ BỊ CƠ QUAN PHÁT HÀNH THU HỒI!",
                "badge_class": "badge-warning",
                "computed_hash": computed_hash,
                "expected_hash": expected_hash,
                "signature_valid": True,
                "document": doc,
                "revocation_reason": doc.get("revocation_reason", "Thu hồi theo quy định"),
                "revoked_at": doc.get("revoked_at"),
                "explanation": (
                    f"Văn bản này từng được phát hành chính thức, nhưng ĐÃ BỊ THU HỒI vào lúc {doc.get('revoked_at')}. "
                    f"Lý do thu hồi: {doc.get('revocation_reason')}."
                )
            }

        # Step 6: Full Pass - Verified Authentic
        return {
            "status": "VERIFIED_AUTHENTIC",
            "verdict_title": "XÁC MINH THÀNH CÔNG: VĂN BẢN NGUYÊN BẢN VÀ CHÍNH GỐC 100%",
            "badge_class": "badge-success",
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "signature_valid": True,
            "document": doc,
            "explanation": (
                f"Văn bản hoàn toàn toàn vẹn và khớp từng byte với bản gốc do {doc['issuer_name']} ban hành "
                f"vào ngày {doc['issued_at']}. Chữ ký số RSA-2048 hoàn toàn hợp lệ."
            )
        }
