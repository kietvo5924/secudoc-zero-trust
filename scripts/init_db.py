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
from src.config import DATABASE_PATH


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

        # 1. FORMAT PDF: Bằng Tốt Nghiệp Cử Nhân (Nguyễn Văn An)
        from src.utils.sample_generator import (
            generate_pdf_bytes,
            generate_docx_bytes,
            generate_certificate_png_bytes,
            generate_student_card_jpg_bytes
        )

        pdf_bytes = generate_pdf_bytes(
            title="Bằng Cử Nhân An Toàn Thông Tin",
            recipient="Nguyễn Văn An",
            details=[
                "Nganh dao tao: AN TOAN THONG TIN VA HE THONG",
                "Xep loai tot nghiep: XUAT SAC",
                "Diem trung binh tich luy (GPA): 3.92 / 4.0",
                "Hieu truong: DA KY SO RSA-2048 VA DONG BLOCK SO CAI"
            ]
        )
        doc_pdf = doc_svc.issue_document(
            issuer_id=1,
            title="Bằng Cử Nhân An Toàn Thông Tin (PDF) - Nguyễn Văn An",
            recipient_name="Nguyễn Văn An",
            doc_type="DIPLOMA",
            file_bytes=pdf_bytes,
            original_filename="Bang_Tot_Nghiep_Nguyen_Van_An.pdf"
        )
        print(f"[+] [PDF] Đã phát hành: {doc_pdf['title']} (UUID: {doc_pdf['doc_uuid']})")

        # 2. FORMAT DOCX: Bảng Điểm Toàn Khóa (Trần Thị Bích)
        docx_bytes = generate_docx_bytes(
            title="BẢNG ĐIỂM HỌC TẬP TOÀN KHÓA CHÍNH QUY",
            recipient="Trần Thị Bích",
            mssv="20260042",
            courses=[
                ("Bảo Mật Mạng Máy Tính & Hệ Thống", "4", "10.0"),
                ("Mật Mã Học Cơ Sở & Ứng Dụng", "3", "9.5"),
                ("Lập Trình An Toàn & Phân Tích Mã Độc", "4", "9.8"),
                ("Kiến Trúc Zero-Trust & Quản Lý Định Danh", "3", "9.8")
            ],
            gpa_str="3.88 / 4.0 (9.77 / 10.0)"
        )
        doc_docx = doc_svc.issue_document(
            issuer_id=1,
            title="Bảng Điểm Toàn Khóa (DOCX) - Trần Thị Bích",
            recipient_name="Trần Thị Bích",
            doc_type="TRANSCRIPT",
            file_bytes=docx_bytes,
            original_filename="Bang_Diem_Tran_Thi_Bich.docx"
        )
        print(f"[+] [DOCX] Đã phát hành: {doc_docx['title']} (UUID: {doc_docx['doc_uuid']})")

        # 3. FORMAT PNG: Giấy Khen Sinh Viên Xuất Sắc (Trần Thị Bích)
        png_bytes = generate_certificate_png_bytes(
            title="GIAY KHEN SINH VIEN XUAT SAC",
            recipient="Trần Thị Bích",
            reason="Dat thanh tich thu khoa Khoa Bao mat Mang nam hoc 2025-2026",
            is_revoked=False
        )
        doc_png = doc_svc.issue_document(
            issuer_id=1,
            title="Giấy Khen Sinh Viên Xuất Sắc (PNG) - Trần Thị Bích",
            recipient_name="Trần Thị Bích",
            doc_type="CERTIFICATE",
            file_bytes=png_bytes,
            original_filename="Giay_Khen_Sinh_Vien_Xuat_Sac.png"
        )
        print(f"[+] [PNG] Đã phát hành: {doc_png['title']} (UUID: {doc_png['doc_uuid']})")

        # 4. FORMAT PNG REVOKED: Chứng Nhận Kỹ Thuật Viên (Lê Hoàng Phúc - Thu hồi)
        png_revoked_bytes = generate_certificate_png_bytes(
            title="CHUNG NHAN HOAN THANH KHOA HOC",
            recipient="Lê Hoàng Phúc",
            reason="Khoa hoc An ninh mang can ban (Vi pham quy che - Da bi thu hoi)",
            is_revoked=True
        )
        doc_png_revoked = doc_svc.issue_document(
            issuer_id=1,
            title="Chứng Nhận Kỹ Thuật Viên (PNG - Đã Thu Hồi) - Lê Hoàng Phúc",
            recipient_name="Lê Hoàng Phúc",
            doc_type="CERTIFICATE",
            file_bytes=png_revoked_bytes,
            original_filename="Chung_Nhan_Ky_Thuat_Vien_Phuc.png"
        )
        doc_svc.revoke_document(
            doc_uuid=doc_png_revoked["doc_uuid"],
            revoked_by=1,
            reason="Thu hồi chứng nhận do học viên vi phạm quy chế thi cử và làm sai lệch hồ sơ đầu vào"
        )
        print(f"[+] [PNG] Đã phát hành & THU HỒI: {doc_png_revoked['title']} (UUID: {doc_png_revoked['doc_uuid']})")

        # 5. FORMAT JPG: Thẻ Sinh Viên Xác Thực Số (Lê Hoàng Phúc)
        jpg_bytes = generate_student_card_jpg_bytes(
            recipient="Lê Hoàng Phúc",
            mssv="20260088",
            dept="Khoa An Toàn Thông Tin",
            valid_until="31/12/2028"
        )
        doc_jpg = doc_svc.issue_document(
            issuer_id=1,
            title="Thẻ Sinh Viên Điện Tử (JPG) - Lê Hoàng Phúc",
            recipient_name="Lê Hoàng Phúc",
            doc_type="OFFICIAL_LETTER",
            file_bytes=jpg_bytes,
            original_filename="The_Sinh_Vien_Le_Hoang_Phuc.jpg"
        )
        print(f"[+] [JPG] Đã phát hành: {doc_jpg['title']} (UUID: {doc_jpg['doc_uuid']})")

        # 6. FORMAT TXT: Bằng Tốt Nghiệp Văn Bản (Nguyễn Văn An)
        doc_txt_content = (
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
        doc_txt = doc_svc.issue_document(
            issuer_id=1,
            title="Bằng Cử Nhân An Toàn Thông Tin (TXT) - Nguyễn Văn An",
            recipient_name="Nguyễn Văn An",
            doc_type="DIPLOMA",
            file_bytes=doc_txt_content,
            original_filename="Bang_Tot_Nghiep_Nguyen_Van_An.txt"
        )
        print(f"[+] [TXT] Đã phát hành: {doc_txt['title']} (UUID: {doc_txt['doc_uuid']})")

        # 7. FORMAT TXT REVOKED: Chứng Chỉ Lê Hoàng Phúc (Đã Thu Hồi)
        doc_txt_rev_content = (
            "TRUONG DAI HOC CONG NGHE THONG TIN - TRUNG TAM TIN HOC\n"
            "CHUNG CHI HOAN THANH KHOA HOC AN NINH MANG CAN BAN\n"
            "Hoc vien: LE HOANG PHUC - Diem: 5.0\n"
        ).encode("utf-8")
        doc_txt_rev = doc_svc.issue_document(
            issuer_id=1,
            title="Chứng Chỉ An Ninh Mạng (TXT - Đã Thu Hồi) - Lê Hoàng Phúc",
            recipient_name="Lê Hoàng Phúc",
            doc_type="CERTIFICATE",
            file_bytes=doc_txt_rev_content,
            original_filename="Chung_Chi_Le_Hoang_Phuc.txt"
        )
        doc_svc.revoke_document(
            doc_uuid=doc_txt_rev["doc_uuid"],
            revoked_by=1,
            reason="Thu hồi chứng chỉ do gian lận trong kỳ thi thực hành"
        )
        print(f"[+] [TXT] Đã phát hành & THU HỒI: {doc_txt_rev['title']} (UUID: {doc_txt_rev['doc_uuid']})")

    print("[✓] Cơ sở dữ liệu và dữ liệu mẫu 5 định dạng (PDF, DOCX, PNG, JPG, TXT) đã sẵn sàng 100%!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Initialize SecuDoc database schema and optional demo fixtures.")
    parser.add_argument("--seed-demo", action="store_true", default=True, help="Seed sample users and demo documents (Default: True)")
    parser.add_argument("--clean", action="store_true", help="Clean/reset database before initializing")
    args = parser.parse_args()

    if args.clean:
        db_file = Path(DATABASE_PATH)
        if db_file.exists():
            db_file.unlink()
            print(f"[*] Đã xóa cơ sở dữ liệu cũ: {db_file}")

    seed_sample_environment()

