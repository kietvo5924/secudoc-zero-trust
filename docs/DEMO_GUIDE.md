# HƯỚNG DẪN TRÌNH DIỄN VÀ DEMO HỆ THỐNG (DEMO GUIDE)
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  

---

## 1. CHUẨN BỊ MÔI TRƯỜNG TRƯỚC BUỔI THUYẾT TRÌNH

### 1.1. Khởi tạo Cơ sở Dữ liệu & Dữ liệu Mẫu (Chạy 1 lần duy nhất)
Mở PowerShell tại thư mục dự án và chạy:
```powershell
python scripts/init_db.py
```
*Kết quả:* Hệ thống sẽ tự động sinh cặp khóa RSA-2048, tạo bảng SQLite, cấp 3 tài khoản demo và phát hành sẵn 3 văn bản mẫu.

### 1.2. Khởi Chạy Ứng Dụng Web Demo
```powershell
python run_web.py
```
*Truy cập trình duyệt tại địa chỉ:* `http://127.0.0.1:5000`

---

## 2. KỊCH BẢN TRÌNH DIỄN TỪNG BƯỚC (STEP-BY-STEP DEMO SCRIPT)

### BƯỚC 1: Trình diễn Cổng Thẩm Định Công Khai & Chế Độ Riêng Tư Web Crypto
- **Mục tiêu:** Cho giảng viên thấy thẩm định Zero-Trust 2 chế độ: Tiêu chuẩn và Riêng tư tuyệt đối (0 byte upload).
- **Thao tác 1 (Chế độ Tiêu chuẩn):**
  1. Mở trang chủ `http://127.0.0.1:5000`.
  2. Mở thư mục `samples/` trong dự án, kéo thả tệp `Bang_Tot_Nghiep_Nguyen_Van_An.txt` vào ô dropzone.
  3. Bấm **"Thẩm Định Toán Học Ngay Lập Tức"**.
  4. Hệ thống trả về thẻ màu xanh lá: **`XÁC MINH THÀNH CÔNG: VĂN BẢN NGUYÊN BẢN VÀ CHÍNH GỐC 100%`**.
  5. Bấm nút **"📜 Mở Phiếu Chứng Thực Số & Quét QR Code"** -> Trình duyệt hiển thị Giấy chứng nhận số trang trọng với mã QR mật mã và con dấu số.
- **Thao tác 2 (Chế độ Riêng tư Web Crypto - Đỉnh cao WOW):**
  1. Trên trang chủ, bấm chuyển sang tab: **"🔒 Chế Độ 2: Thẩm Định Riêng Tư (Web Crypto - 0 Byte Upload)"**.
  2. Kéo thả tệp bất kỳ từ `samples/`. Trình duyệt lập tức băm SHA-256 ngay trong RAM bằng Web Crypto API và trả về kết quả tức thì.
  3. Thuyết minh: *"Hệ thống tuân thủ Nghị định 13/2023/NĐ-CP và GDPR, bảo vệ dữ liệu nhạy cảm của ứng viên khi 0 byte nội dung bị gửi lên mạng!"*

---

### BƯỚC 2: Mô Phỏng Tấn Công Can Thiệp Dữ Liệu 1-Bit (Kính Hiển Vi Soi Byte & Ma Trận Tuyết Lở)
- **Mục tiêu:** Chứng minh nguyên tắc *"Không tin tưởng đầu vào"* bằng hiệu ứng thị giác trực quan.
- **Thao tác:**
  1. Bấm vào menu **Attack Lab ⚡** (`http://127.0.0.1:5000/attack-lab`).
  2. Tại **Kịch Bản 1**, bấm nút màu đỏ: **"💥 Thực Thi Đảo 1 Bit & Thẩm Định Ngay"**.
- **Quan sát kết quả (Yếu tố WOW):**
  - Hệ thống trả về thẻ cảnh báo màu đỏ: **`CẢNH BÁO: VĂN BẢN ĐÃ BỊ CAN THIỆP / SỬA ĐỔI NỘI DUNG!`**.
  - **Kính hiển vi soi từng byte (Byte Forensic Inspector):** Chỉ rõ ký tự gốc `'T'` (Hex: `0x54`, Bin: `01010100`) bị đảo 1 bit thành `'U'` (Hex: `0x55`, Bin: `01010101`).
  - **Ma trận tuyết lở 256-bit (Avalanche Heatmap):** 256 ô vuông hiển thị trực tiếp các bit SHA-256 đổi màu đỏ rực rỡ (~50% bits đảo chiều), chứng minh tính toán học không thể giả mạo.

---

### BƯỚC 3: Mô Phỏng Giả Mạo Chữ Ký Số Bằng Khóa Lạ (Signature Forgery Attack)
- **Mục tiêu:** Trả lời câu hỏi *"Nếu kẻ gian tự làm bằng giả rồi tự ký số thì sao?"*.
- **Thao tác:**
  1. Vẫn tại trang **Attack Lab**, kéo xuống **Kịch Bản 2**.
  2. Bấm nút màu vàng: **"⚡ Sinh Khóa Rogue & Thử Nghiệm Giả Mạo"**.
- **Quan sát kết quả:**
  - Kẻ tấn công sinh cặp khóa RSA-2048 riêng và ký số lên tài liệu.
  - Nhưng khi đối soát với **Khóa Công Khai Gốc (Root Public Key)** của Nhà trường, hàm `verify_signature()` trả về **`FALSE`**.
  - Thẻ kết quả màu đỏ hiển thị: **`🚨 TẤN CÔNG GIẢ MẠO CHỮ KÝ BỊ CHẶN HOÀN TOÀN!`**.

---

### BƯỚC 4: Quy Trình Phát Hành và Thu Hồi Văn Bản của Issuer
- **Mục tiêu:** Thể hiện phân quyền RBAC và khả năng thu hồi văn bản kỷ luật.
- **Thao tác:**
  1. Bấm **"Đăng Nhập Quản Trị"** -> Đăng nhập tài khoản: `issuer` / `IssuerSecurePass2026!`.
  2. Tự động chuyển đến **Bảng Điều Khiển Phát Hành (Dashboard)**.
  3. Điền thông tin phát hành:
     - Tiêu đề: *Chứng Chỉ Hoàn Thành Đồ Án Cuối Kỳ*
     - Người nhận: *Sinh Viên Demo - MSSV: 20269999*
     - Loại: *CERTIFICATE*
     - Chọn 1 file bất kỳ (.txt hoặc .pdf).
  4. Bấm **"Ký Số RSA-2048 & Đóng Block Sổ Cái"**.
  5. Thấy văn bản mới xuất hiện trong danh sách kèm chữ ký số và mã băm.
  6. Tại cột Thao Tác, bấm nút màu đỏ **"Thu Hồi"** -> Xác nhận.
  7. Văn bản lập tức chuyển trạng thái sang **`● Đã thu hồi`**.

---

### BƯỚC 5: Kiểm Toán Viên Giám Sát Sổ Cái Mật Mã Bất Biến (Auditor View)
- **Mục tiêu:** Minh họa cấu trúc liên kết khối (Hash Chain) chống sửa đổi cơ sở dữ liệu nội bộ.
- **Thao tác:**
  1. Đăng xuất và đăng nhập lại bằng tài khoản: `auditor` / `AuditorPass2026!`.
  2. Truy cập trang **Sổ Cái Kiểm Toán** (`http://127.0.0.1:5000/audit`).
  3. Bấm **"⚡ Quét Toán Học Chuỗi Khối"** -> Nhận thông báo màu xanh lá: *Toàn bộ các khối đều toàn vẹn và liên tục*.
  4. Kéo xuống mục thử nghiệm bên dưới: Bấm **"💥 Can Thiệp Sửa Lén Block 0 & Kiểm Toán Lại"**.
  5. Nhận kết quả cảnh báo màu đỏ tức thì: **`🚨 PHÁT HIỆN CAN THIỆP SỔ CÁI: Đứt gãy liên kết chuỗi tại block 1!`**.

---

## 3. TRÌNH DIỄN NHANH QUA DÒNG LỆNH (HEADLESS CLI DEMO)

Nếu giảng viên muốn kiểm chứng độc lập trực tiếp từ Terminal:
```powershell
# 1. Thẩm định tệp mẫu
python -m src.cli.secu_cli verify Bang_Diem_Tran_Thi_Bich.txt

# 2. Kiểm toán tính toàn vẹn sổ cái
python -m src.cli.secu_cli audit

# 3. Chạy mô phỏng tấn công 1-bit
python -m src.cli.secu_cli attack-demo
```
