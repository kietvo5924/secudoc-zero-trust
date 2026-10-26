"""Export authentic and tampered sample files for live demonstration across all 5 formats."""
import os
import sys
import sqlite3
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from src.utils.sample_generator import (
    generate_pdf_bytes,
    generate_docx_bytes,
    generate_certificate_png_bytes,
    generate_student_card_jpg_bytes
)

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
DB_PATH = BASE_DIR / "data" / "secudoc.db"

def export_samples():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    docs = conn.execute("SELECT * FROM documents").fetchall()

    doc_map = {}
    for doc in docs:
        storage_path = Path(doc["file_storage_path"])
        if storage_path.exists():
            dest = SAMPLES_DIR / doc["original_filename"]
            content = storage_path.read_bytes()
            dest.write_bytes(content)
            doc_map[doc["original_filename"]] = dict(doc)
            print(f"[+] Đã xuất file mẫu gốc: {dest.name} ({len(content)} bytes)")

    # 1. Tampered PDF (Altered GPA from 3.92 to 4.00)
    tampered_pdf = generate_pdf_bytes(
        title="Bằng Cử Nhân An Toàn Thông Tin",
        recipient="Nguyễn Văn An",
        details=[
            "Nganh dao tao: AN TOAN THONG TIN VA HE THONG",
            "Xep loai tot nghiep: XUAT SAC",
            "Diem trung binh tich luy (GPA): 4.00 / 4.0 (DA SUA DIEM GIAN LAN)",
            "Hieu truong: DA KY SO RSA-2048 VA DONG BLOCK SO CAI"
        ]
    )
    (SAMPLES_DIR / "Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.pdf").write_bytes(tampered_pdf)
    print("[+] Đã tạo file PDF giả mạo sửa điểm: Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.pdf")

    # 2. Tampered DOCX (Altered course scores to 10.0)
    tampered_docx = generate_docx_bytes(
        title="BẢNG ĐIỂM HỌC TẬP TOÀN KHÓA CHÍNH QUY (ĐÃ SỬA ĐIỂM)",
        recipient="Trần Thị Bích",
        mssv="20260042",
        courses=[
            ("Bảo Mật Mạng Máy Tính & Hệ Thống", "4", "10.0"),
            ("Mật Mã Học Cơ Sở & Ứng Dụng", "3", "10.0 (SỬA TỪ 9.5)"),
            ("Lập Trình An Toàn & Phân Tích Mã Độc", "4", "10.0 (SỬA TỪ 9.8)"),
            ("Kiến Trúc Zero-Trust & Quản Lý Định Danh", "3", "10.0")
        ],
        gpa_str="4.00 / 4.0 (10.0 / 10.0 - GIAN LẬN)"
    )
    (SAMPLES_DIR / "Bang_Diem_Tran_Thi_Bich_TAMPERED.docx").write_bytes(tampered_docx)
    print("[+] Đã tạo file DOCX giả mạo sửa điểm: Bang_Diem_Tran_Thi_Bich_TAMPERED.docx")

    # 3. Tampered PNG Certificate
    tampered_png = generate_certificate_png_bytes(
        title="GIAY KHEN SINH VIEN XUAT SAC (DA SUA TEN)",
        recipient="LE VAN GIA MAO (TAMPERED)",
        reason="Dat thanh tich thu khoa Khoa Bao mat Mang nam hoc 2025-2026",
        is_revoked=False
    )
    (SAMPLES_DIR / "Giay_Khen_Sinh_Vien_TAMPERED.png").write_bytes(tampered_png)
    print("[+] Đã tạo file PNG giả mạo đổi tên: Giay_Khen_Sinh_Vien_TAMPERED.png")

    # 4. Tampered JPG Student Card
    tampered_jpg = generate_student_card_jpg_bytes(
        recipient="LE HOANG PHUC (THE GIA MAO)",
        mssv="99999999 (FAKE)",
        dept="Khoa An Toàn Thông Tin",
        valid_until="31/12/2099"
    )
    (SAMPLES_DIR / "The_Sinh_Vien_TAMPERED.jpg").write_bytes(tampered_jpg)
    print("[+] Đã tạo file JPG thẻ sinh viên giả mạo: The_Sinh_Vien_TAMPERED.jpg")

    # 5. Tampered TXT
    doc_txt = SAMPLES_DIR / "Bang_Tot_Nghiep_Nguyen_Van_An.txt"
    if doc_txt.exists():
        text = doc_txt.read_text(encoding="utf-8")
        tampered_text = text.replace("GPA): 3.92 / 4.0", "GPA): 4.00 / 4.0 (DA SUA DIEM GIAN LAN)")
        (SAMPLES_DIR / "Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt").write_text(tampered_text, encoding="utf-8")
        print("[+] Đã tạo file TXT sửa điểm: Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt")

    # 6. Untrusted / Fake Diploma (PDF and TXT)
    fake_txt = (
        "TRUONG DAI HOC KHONG RO NGUON GOC\n"
        "BANG TOT NGHIEP GIA MAO\n"
        "Sinh vien: LE VAN GIA - Xep loai: XUAT SAC\n"
    )
    (SAMPLES_DIR / "Bang_Gia_Mao_Chua_Tung_Dang_Ky.txt").write_text(fake_txt, encoding="utf-8")
    
    fake_pdf = generate_pdf_bytes(
        title="BANG TOT NGHIEP GIA MAO",
        recipient="LE VAN GIA",
        details=[
            "Truong dai hoc khong ro nguon goc",
            "Chua tung dang ky vao he thong SecuDoc",
            "Chung chi khong hop le"
        ]
    )
    (SAMPLES_DIR / "Bang_Gia_Mao_Chua_Tung_Dang_Ky.pdf").write_bytes(fake_pdf)
    print("[+] Đã tạo file văn bản trôi nổi chưa đăng ký (TXT & PDF)")

    # 7. Create Guide file in samples
    pdf_uuid = doc_map.get("Bang_Tot_Nghiep_Nguyen_Van_An.pdf", {}).get("doc_uuid", "")
    docx_uuid = doc_map.get("Bang_Diem_Tran_Thi_Bich.docx", {}).get("doc_uuid", "")
    png_uuid = doc_map.get("Giay_Khen_Sinh_Vien_Xuat_Sac.png", {}).get("doc_uuid", "")
    png_rev_uuid = doc_map.get("Chung_Nhan_Ky_Thuat_Vien_Phuc.png", {}).get("doc_uuid", "")
    jpg_uuid = doc_map.get("The_Sinh_Vien_Le_Hoang_Phuc.jpg", {}).get("doc_uuid", "")
    txt_uuid = doc_map.get("Bang_Tot_Nghiep_Nguyen_Van_An.txt", {}).get("doc_uuid", "")
    txt_rev_uuid = doc_map.get("Chung_Chi_Le_Hoang_Phuc.txt", {}).get("doc_uuid", "")

    guide_content = f"""BẢNG DANH MỤC TỆP MẪU 5 ĐỊNH DẠNG (PDF, DOCX, PNG, JPG, TXT) KHI DEMO
================================================================================
Hệ thống SecuDoc hỗ trợ đầy đủ 5 định dạng tệp. Khi kéo thả tệp vào web, hệ thống
sẽ băm SHA-256 các byte nhị phân và đối soát chữ ký số RSA-2048 / Sổ cái Blockchain.

1. ĐỊNH DẠNG PDF:
   - Bang_Tot_Nghiep_Nguyen_Van_An.pdf
     UUID: {pdf_uuid}
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Hợp lệ 100%)
   - Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.pdf
     UUID: {pdf_uuid} (nhập UUID để đối soát)
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện sửa điểm GPA từ 3.92 lên 4.00)

2. ĐỊNH DẠNG DOCX (Word):
   - Bang_Diem_Tran_Thi_Bich.docx
     UUID: {docx_uuid}
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Bảng điểm chính quy hợp lệ)
   - Bang_Diem_Tran_Thi_Bich_TAMPERED.docx
     UUID: {docx_uuid}
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện sửa điểm môn học trong file Word)

3. ĐỊNH DẠNG PNG (Hình ảnh):
   - Giay_Khen_Sinh_Vien_Xuat_Sac.png
     UUID: {png_uuid}
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Giấy khen đồ họa hợp lệ)
   - Giay_Khen_Sinh_Vien_TAMPERED.png
     UUID: {png_uuid}
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện chỉnh sửa đồ họa/đổi tên)
   - Chung_Nhan_Ky_Thuat_Vien_Phuc.png
     UUID: {png_rev_uuid}
     -> Kết quả: VÀNG CAM (REVOKED - Đã bị thu hồi do kỷ luật)

4. ĐỊNH DẠNG JPG (Hình ảnh / Thẻ sinh viên):
   - The_Sinh_Vien_Le_Hoang_Phuc.jpg
     UUID: {jpg_uuid}
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Thẻ sinh viên điện tử hợp lệ)
   - The_Sinh_Vien_TAMPERED.jpg
     UUID: {jpg_uuid}
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Thẻ sinh viên bị can thiệp dữ liệu)

5. ĐỊNH DẠNG TXT (Văn bản thuần):
   - Bang_Tot_Nghiep_Nguyen_Van_An.txt
     UUID: {txt_uuid}
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC)
   - Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt
     UUID: {txt_uuid}
     -> Kết quả: ĐỎ (TAMPERED_CONTENT)
   - Chung_Chi_Le_Hoang_Phuc.txt
     UUID: {txt_rev_uuid}
     -> Kết quả: VÀNG CAM (REVOKED)

6. TỆP TRÔI NỔI / CHƯA ĐĂNG KÝ:
   - Bang_Gia_Mao_Chua_Tung_Dang_Ky.pdf
   - Bang_Gia_Mao_Chua_Tung_Dang_Ky.txt
     -> Kết quả: KHÔNG TÌM THẤY TRONG HỆ THỐNG (NOT_FOUND / UNTRUSTED)
================================================================================
"""
    (SAMPLES_DIR / "README_DEMO_SAMPLES.txt").write_text(guide_content, encoding="utf-8")
    print("[+] Đã tạo tài liệu hướng dẫn kéo thả: README_DEMO_SAMPLES.txt")

if __name__ == "__main__":
    export_samples()
