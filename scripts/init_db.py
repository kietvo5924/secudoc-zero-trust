"""Database initialization and sample data seeder for SecuDoc."""
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from src.models.database import DatabaseManager, get_db
from src.crypto.keys import KeyManager
from src.services.doc_service import DocumentService


def seed_sample_environment():
    """Initialize database schema, keys, and issue sample academic documents."""
    print("[*] Khởi tạo Database Manager và Key Manager...")
    db = get_db()
    key_mgr = KeyManager()
    key_mgr.ensure_keys_exist()
    print(f"[+] Khóa RSA-2048 đã sẵn sàng tại: {key_mgr.private_path.parent}")

    doc_svc = DocumentService(db, key_mgr)

    # Check if sample documents already exist
    existing = doc_svc.list_documents(limit=10)
    if not existing:
        print("[*] Đang phát hành văn bản mẫu...")

        # Sample Doc 1: Bang Tot Nghiep
        doc1_content = (
            "TRUONG DAI HOC CONG NGHE THONG TIN - KHOA AN TOAN THONG TIN\n"
            "===========================================================\n"
            "BANG TOT NGHIEP DAI HOC CHINH QUY\n"
            "Cap cho: NGUYEN VAN AN\n"
            "Ngay sinh: 15/08/2004\n"
            "Nganh dao tao: AN TOAN THONG TIN\n"
            "Xep loai tot nghiep: XUAT SAC\n"
            "Diem trung binh tich luy (GPA): 3.92 / 4.0\n"
            "Hieu truong: DA KY SO VA XAC THUC DIEN TU\n"
        ).encode("utf-8")

        doc1 = doc_svc.issue_document(
            issuer_id=1,
            title="Bằng Cử Nhân An Toàn Thông Tin - Nguyễn Văn An",
            recipient_name="Nguyễn Văn An",
            doc_type="DIPLOMA",
            file_bytes=doc1_content,
            original_filename="Bang_Tot_Nghiep_Nguyen_Van_An.txt"
        )
        print(f"[+] Đã phát hành Văn bản 1: {doc1['title']} (UUID: {doc1['doc_uuid']})")

        # Sample Doc 2: Bang Diem
        doc2_content = (
            "TRUONG DAI HOC CONG NGHE THONG TIN - PHONG DAO TAO\n"
            "==================================================\n"
            "BANG DIEM KET QUA HOC TAP TOAN KHOA\n"
            "Sinh vien: TRAN THI BICH - MSSV: 20260042\n"
            "Mon 1: Bao Mat Mang May Tinh va He Thong - Diem: 10.0\n"
            "Mon 2: Mat Ma Hoc Co So va Ung Dung - Diem: 9.5\n"
            "Mon 3: Lap Trinh An Toan - Diem: 9.8\n"
            "Xep loai chung: XUAT SAC\n"
        ).encode("utf-8")

        doc2 = doc_svc.issue_document(
            issuer_id=1,
            title="Bảng Điểm Toàn Khóa - Trần Thị Bích",
            recipient_name="Trần Thị Bích",
            doc_type="TRANSCRIPT",
            file_bytes=doc2_content,
            original_filename="Bang_Diem_Tran_Thi_Bich.txt"
        )
        print(f"[+] Đã phát hành Văn bản 2: {doc2['title']} (UUID: {doc2['doc_uuid']})")

        # Sample Doc 3: Chung Chi Ky Thuat Vien (Revoked for demonstration)
        doc3_content = (
            "TRUONG DAI HOC CONG NGHE THONG TIN - TRUNG TAM TIN HOC\n"
            "CHUNG CHI HOAN THANH KHOA HOC AN NINH MANG CAN BAN\n"
            "Hoc vien: LE HOANG PHUC - Diem: 5.0\n"
        ).encode("utf-8")

        doc3 = doc_svc.issue_document(
            issuer_id=1,
            title="Chứng Chỉ An Ninh Mạng - Lê Hoàng Phúc (Đã Thu Hồi)",
            recipient_name="Lê Hoàng Phúc",
            doc_type="CERTIFICATE",
            file_bytes=doc3_content,
            original_filename="Chung_Chi_Le_Hoang_Phuc.txt"
        )
        # Immediately revoke doc3 to provide sample revoked document
        doc_svc.revoke_document(
            doc_uuid=doc3["doc_uuid"],
            revoked_by=1,
            reason="Thu hồi chứng chỉ do học viên vi phạm quy chế thi cử và làm sai lệch hồ sơ đầu vào"
        )
        print(f"[+] Đã phát hành và thu hồi Văn bản 3: {doc3['title']} (UUID: {doc3['doc_uuid']})")

    print("[✓] Cơ sở dữ liệu và dữ liệu mẫu đã sẵn sàng 100%!")


if __name__ == "__main__":
    seed_sample_environment()
