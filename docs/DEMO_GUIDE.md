# HƯỚNG DẪN TRÌNH DIỄN VÀ DEMO HỆ THỐNG (DEMO GUIDE)
**Dự án:** SecuDoc — Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  

---

## 1. CHUẨN BỊ MÔI TRƯỜNG TRƯỚC BUỔI THUYẾT TRÌNH

### 1.1. Khởi tạo Cơ sở Dữ liệu & Dữ liệu Mẫu (Chạy 1 lần duy nhất)
Mở PowerShell tại thư mục dự án và chạy:
```powershell
python scripts/init_db.py --seed-demo
```
*Kết quả:* Hệ thống sẽ tự động khởi tạo cặp khóa RSA-2048 (nếu chưa có), tạo bảng SQLite, cấp 3 tài khoản demo và phát hành sẵn 3 văn bản mẫu trong CSDL.

### 1.2. Khởi Chạy Ứng Dụng Web Demo
```powershell
python run_web.py
```
*Truy cập trình duyệt tại địa chỉ:* `http://127.0.0.1:5000`

---

## 2. KỊCH BẢN TRÌNH DIỄN TỪNG BƯỚC (STEP-BY-STEP DEMO SCRIPT)

### BƯỚC 1: Cổng Thẩm Định Công Khai & Quét Mã QR Thật
- **Mục tiêu:** Cho giảng viên thấy thẩm định Zero-Trust 2 chế độ: Tiêu chuẩn và Giảm thiểu dữ liệu (Client-side SHA-256).
- **Thao tác 1 (Chế độ Tiêu chuẩn & Quét QR):**
  1. Mở trang chủ `http://127.0.0.1:5000`.
  2. Mở thư mục `samples/` trong dự án, kéo thả tệp `Bang_Tot_Nghiep_Nguyen_Van_An.txt` vào ô dropzone.
  3. Bấm **"Thẩm Định Toán Học Ngay Lập Tức"**.
  4. Hệ thống trả về thẻ màu xanh lá: **`XÁC MINH THÀNH CÔNG: VĂN BẢN NGUYÊN BẢN VÀ CHÍNH GỐC 100%`**.
  5. Bấm nút **"📜 Mở Phiếu Chứng Thực Số & Quét QR Code"** -> Trình duyệt hiển thị Giấy chứng nhận số trang trọng với mã QR chuẩn và mã băm vân tay khóa gốc (`SHA256:XX:XX:...`).
  6. **Trình diễn quét QR:** Mở camera điện thoại quét mã QR trên màn hình. Điện thoại nhận diện chính xác link `http://<host>:5000/verify?uuid=...` và mở trang đối soát tài liệu tương ứng.
- **Thao tác 2 (Chế độ Giảm thiểu dữ liệu Client-Side SHA-256):**
  1. Trên trang chủ, bấm chuyển sang tab: **"🔒 Chế Độ 2: Thẩm Định Giảm Thiểu Dữ Liệu (Client-Side SHA-256)"**.
  2. Kéo thả tệp bất kỳ từ `samples/`. Trình duyệt lập tức băm SHA-256 ngay trong RAM bằng Web Crypto API và gửi hash lên máy chủ để tra cứu.
  3. **Thuyết minh kỹ thuật:** *"Hệ thống áp dụng nguyên tắc Giảm thiểu Dữ liệu (Data Minimization Principle): nội dung tệp nhạy cảm không truyền qua mạng; chỉ mã băm 64 ký tự và mã UUID được gửi lên máy chủ để tra cứu trạng thái thu hồi và đối soát chữ ký số."*

---

### BƯỚC 2: Mô Phỏng Tấn Công Can Thiệp Dữ Liệu 1-Bit (Kính Hiển Vi Soi Byte & Ma Trận Tuyết Lở)
- **Mục tiêu:** Chứng minh nguyên tắc *"Không tin tưởng đầu vào"* bằng hiệu ứng thị giác trực quan.
- **Thao tác:**
  1. Bấm vào menu **Attack Lab ⚡** (`http://127.0.0.1:5000/attack-lab`).
  2. Tại **Kịch Bản 1**, bấm nút màu đỏ: **"💥 Thực Thi Đảo 1 Bit & Thẩm Định Ngay"**.
- **Quan sát kết quả:**
  - Hệ thống trả về thẻ cảnh báo màu đỏ: **`CẢNH BÁO: VĂN BẢN ĐÃ BỊ CAN THIỆP / SỬA ĐỔI NỘI DUNG!`**.
  - **Kính hiển vi soi từng byte (Byte Forensic Inspector):** Chỉ rõ ký tự gốc `'T'` (Hex: `0x54`, Bin: `01010100`) bị đảo 1 bit thành `'U'` (Hex: `0x55`, Bin: `01010101`).
  - **Ma trận tuyết lở 256-bit (Avalanche Heatmap):** 256 ô vuông hiển thị trực tiếp các bit SHA-256 đổi màu (~50% bits đảo chiều), chứng minh tính toán học không thể giả mạo.

---

### BƯỚC 3: Mô Phỏng Giả Mạo Chữ Ký Số Bằng Khóa Lạ (Signature Forgery Attack)
- **Mục tiêu:** Trả lời câu hỏi *"Nếu kẻ gian tự làm bằng giả rồi tự ký số thì sao?"*.
- **Thao tác:**
  1. Vẫn tại trang **Attack Lab**, kéo xuống **Kịch Bản 2**.
  2. Bấm nút màu vàng: **"⚡ Sinh Khóa Rogue & Thử Nghiệm Giả Mạo"**.
- **Quan sát kết quả:**
  - Kẻ tấn công sinh cặp khóa RSA-2048 riêng và ký số lên tài liệu.
  - Khi đối soát với **Khóa Công Khai Gốc (Root Public Key)** của Nhà trường, hàm `verify_signature()` trả về **`FALSE`**.
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
     - Chọn 1 file (.txt hoặc .pdf) dưới 10MB.
  4. Bấm **"Ký Số RSA-2048 & Đóng Block Sổ Cái"**.
  5. Thấy văn bản mới xuất hiện trong danh sách kèm chữ ký số và mã băm.
  6. Tại cột Thao Tác, bấm nút màu đỏ **"Thu Hồi"** -> Điền lý do thu hồi -> Xác nhận.
  7. Văn bản chuyển trạng thái sang **`● Đã thu hồi`**. Kéo thả tệp này vào trang chủ thẩm định sẽ nhận verdict: **`REVOKED: Văn bản đã bị thu hồi kỷ luật`**.

---

### BƯỚC 5: Kiểm Toán Viên Giám Sát Sổ Cái Mật Mã Cô Lập (Auditor View)
- **Mục tiêu:** Minh họa cấu trúc liên kết chuỗi khối (Cryptographic Hash-Chain) chống sửa đổi cơ sở dữ liệu nội bộ.
- **Thao tác:**
  1. Đăng xuất và đăng nhập lại bằng tài khoản: `auditor` / `AuditorPass2026!`.
  2. Truy cập trang **Sổ Cái Kiểm Toán** (`http://127.0.0.1:5000/audit`).
  3. Bấm **"⚡ Quét Toán Học Chuỗi Khối"** -> Nhận thông báo màu xanh lá: *Toàn bộ các khối đều toàn vẹn và liên tục*.
  4. Thử nghiệm diễn tập can thiệp CSDL: Bấm **"💥 Can Thiệp Sửa Lén Block 0 & Kiểm Toán Lại"**.
  5. Nhận kết quả cảnh báo màu đỏ tức thì: **`🚨 PHÁT HIỆN CAN THIỆP SỔ CÁI: Đứt gãy liên kết chuỗi tại block 1!`**.
  6. Thao tác này chạy an toàn trên cơ sở dữ liệu Sandbox `data/attack_sandbox.db`, không ảnh hưởng đến cơ sở dữ liệu phát hành chính `data/secudoc.db`.
  7. Bấm **"Khôi Phục Block Từ Snapshot Diễn Tập"** để hoàn nguyên dữ liệu Sandbox về trạng thái hợp lệ ban đầu.

---

## 3. TRÌNH DIỄN QUA DÒNG LỆNH (HEADLESS CLI DEMO)

Nếu giảng viên muốn kiểm chứng độc lập trực tiếp từ Terminal:
```powershell
# 1. Thẩm định tệp mẫu
python -m src.cli.secu_cli verify samples/Bang_Tot_Nghiep_Nguyen_Van_An.txt

# 2. Kiểm toán tính toàn vẹn sổ cái
python -m src.cli.secu_cli audit
```

---

## 4. BẢNG CHECKLIST ĐỐI THOẠI TRẢ LỜI CÂU HỎI HỘI ĐỒNG (FAQ DEFENSE)

| Câu Hỏi Khả Dĩ Của Giảng Viên | Câu Trả Lời Ngắn Gọn & Chính Xác Kỹ Thuật |
|:---|:---|
| **"Tại sao gọi là Zero-Trust?"** | Vì hệ thống không tin tưởng đầu vào dựa trên hình thức (tên file, định dạng, hay metadata tự khai). Toàn bộ dữ liệu phải qua 4 bước thẩm định độc lập: băm lại byte, kiểm tra chữ ký RSA, đối soát sự kiện thu hồi trong sổ cái và kiểm tra toàn vẹn chuỗi khối. |
| **"Nếu kẻ gian sửa trực tiếp tên sinh viên trong SQLite thì sao?"** | Chữ ký số RSA của SecuDoc không chỉ ký mã băm tệp mà ký trên **Canonical Metadata Payload** (gồm cả UUID, hash, tên người nhận, loại bằng, thời điểm cấp). Sửa tên người nhận trong SQLite làm sai lệch digest payload, chữ ký số lập tức bị vô hiệu hóa (`INVALID_SIGNATURE`). |
| **"Hệ thống có phải Blockchain phân tán không?"** | Không. Đây là Sổ cái Kiểm toán Chuỗi Khối Mật mã (Cryptographic Hash-Chain) liên kết tuyến tính (`prev_block_hash`), phù hợp với quy mô một trường đại học độc lập. Hệ thống không sử dụng cơ chế đồng thuận phân tán tốn tài nguyên (Proof of Work/Stake). |
| **"Nếu kẻ tấn công chiếm quyền Root server và tính lại toàn bộ hash-chain thì sao?"** | Hash-chain cục bộ phát hiện được các can thiệp sửa đổi đơn lẻ vào các block quá khứ. Nếu kẻ tấn công chiếm toàn quyền kiểm soát máy chủ để tính lại toàn bộ chuỗi (recalculation), hệ thống cần neo đỉnh chuỗi (Head Hash Checkpoint) ra bên ngoài hoặc công bố định kỳ để phát hiện (đã chứng minh trong test case `TC-ATTACK-07`). |
| **"Chế độ Web Crypto có phải Zero-Knowledge Proof không?"** | Không. Đây là kỹ thuật Client-side Hashing theo nguyên tắc Giảm thiểu Dữ liệu (Data Minimization): tệp không truyền qua mạng, nhưng mã băm và UUID vẫn được gửi lên server để kiểm tra trạng thái thu hồi. |
