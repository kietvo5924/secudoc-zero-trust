"""Export authentic and tampered sample files for live demonstration."""
import os
import sys
import sqlite3
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
DB_PATH = BASE_DIR / "data" / "secudoc.db"

def export_samples():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    docs = conn.execute("SELECT * FROM documents").fetchall()

    for doc in docs:
        storage_path = Path(doc["file_storage_path"])
        if storage_path.exists():
            dest = SAMPLES_DIR / doc["original_filename"]
            content = storage_path.read_bytes()
            dest.write_bytes(content)
            print(f"[+] Đã xuất file mẫu gốc: {dest.name} ({len(content)} bytes)")

    # Create Tampered version of Doc 1 (change GPA 3.92 -> 4.00)
    doc1 = SAMPLES_DIR / "Bang_Tot_Nghiep_Nguyen_Van_An.txt"
    if doc1.exists():
        text = doc1.read_text(encoding="utf-8")
        tampered_text = text.replace("GPA): 3.92 / 4.0", "GPA): 4.00 / 4.0 (DA SUA DIEM GIAN LAN)")
        tampered_file = SAMPLES_DIR / "Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt"
        tampered_file.write_text(tampered_text, encoding="utf-8")
        print(f"[+] Đã tạo file giả mạo sửa điểm: {tampered_file.name}")

    # Create Untrusted/Fake Diploma
    fake_content = (
        "TRUONG DAI HOC KHONG RO NGUON GOC\n"
        "BANG TOT NGHIEP GIA MAO\n"
        "Sinh vien: LE VAN GIA - Xep loai: XUAT SAC\n"
    )
    fake_file = SAMPLES_DIR / "Bang_Gia_Mao_Chua_Tung_Dang_Ky.txt"
    fake_file.write_text(fake_content, encoding="utf-8")
    print(f"[+] Đã tạo file chưa đăng ký: {fake_file.name}")

    # Create Guide file in samples
    guide_content = """HƯỚNG DẪN KÉO THẢ TỆP MẪU KHI THUYẾT TRÌNH (DEMO SAMPLES)
============================================================
1. Bang_Tot_Nghiep_Nguyen_Van_An.txt
   -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC)
   -> Chứng minh: Văn bản chính gốc 100%, chữ ký RSA khớp, mã băm SHA-256 khớp.

2. Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt
   -> Nhập kèm UUID của Nguyễn Văn An (hoặc kéo thả)
   -> Kết quả: ĐỎ (TAMPERED_CONTENT)
   -> Chứng minh: Hệ thống phát hiện sửa điểm GPA từ 3.92 thành 4.00 nhờ sai lệch mã băm.

3. Bang_Diem_Tran_Thi_Bich.txt
   -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC)
   -> Chứng minh: Bảng điểm chuẩn của sinh viên Trần Thị Bích.

4. Chung_Chi_Le_Hoang_Phuc.txt
   -> Kết quả: VÀNG (REVOKED)
   -> Chứng minh: Văn bản từng có thật nhưng đã bị thu hồi kỷ luật; hệ thống chặn thành công.

5. Bang_Gia_Mao_Chua_Tung_Dang_Ky.txt
   -> Kết quả: VÀNG/ĐỎ (NOT_FOUND)
   -> Chứng minh: Văn bản trôi nổi bên ngoài, chưa từng được cơ quan cấp ký phát hành.
"""
    (SAMPLES_DIR / "README_DEMO_SAMPLES.txt").write_text(guide_content, encoding="utf-8")
    print(f"[+] Đã tạo tài liệu hướng dẫn kéo thả: README_DEMO_SAMPLES.txt")

if __name__ == "__main__":
    export_samples()
