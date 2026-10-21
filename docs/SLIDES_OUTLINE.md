# ĐỀ CƯƠNG BÀI THUYẾT TRÌNH (SLIDES OUTLINE)
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  
**Đề tài:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Thời lượng dự kiến:** 12 - 15 phút  

---

### SLIDE 1: TRANG TIÊU ĐỀ
- **Tiêu đề chính:** SECUDOC - HỆ THỐNG XÁC MINH CHỨNG THỰC VĂN BẢN SỐ CHỐNG GIẢ MẠO
- **Tiêu đề phụ:** Ứng dụng Nguyên tắc Zero-Trust, Chữ ký số RSA-2048, Mã băm SHA-256 và Sổ cái Bất biến
- **Học phần:** Bảo Mật Mạng Máy Tính và Hệ Thống
- **Thông tin nhóm:** Sinh viên thực hiện (Điền họ tên & MSSV khi nộp bài)
- **Giảng viên hướng dẫn:** (Điền thông tin giảng viên)

---

### SLIDE 2: ĐẶT VẤN ĐỀ VÀ THỰC TRẠNG THỰC TẾ
- **Thực trạng nhức nhối:** Bằng đại học, chứng chỉ ngoại ngữ, bảng điểm, công văn số bị sửa đổi điểm số hoặc chỉnh sửa nội dung bằng các công cụ chỉnh sửa tệp phổ biến.
- **Hậu quả:** Tổn hại danh tiếng trường đại học, tuyển dụng sai nhân sự, phát sinh rủi ro pháp lý và an ninh thông tin.
- **Lỗ hổng của phương pháp cũ:** Mắt thường con người không thể phát hiện tệp PDF bị chỉnh sửa; dấu mộc scanned hoặc logo trên mạng rất dễ bị sao chép; không có cơ chế thu hồi tức thì.

---

### SLIDE 3: NGUYÊN TẮC CỐT LÕI: ZERO-TRUST
- **Tư tưởng chủ đạo:** *"Không phải mọi thông tin mà hệ thống nhận được đều đáng tin cậy."*
- **Quy tắc vàng:** Không tin vào hình ảnh, con dấu, tên tệp hay vẻ ngoài của văn bản.
- **Giải pháp:** Mọi tệp dữ liệu đưa vào hệ thống đều là `UNTRUSTED` cho đến khi được chứng minh bằng các tính toán toán học mật mã học không thể làm giả:
  1. Mã băm SHA-256 phân mảnh (kiểm soát toàn vẹn từng bit).
  2. Chữ ký số RSA-2048 với Khóa riêng của Trường (chứng minh nguồn gốc & chống chối bỏ).
  3. Kiểm tra danh sách thu hồi thời gian thực.
  4. Sổ cái băm Merkle chống sửa đổi lịch sử.

---

### SLIDE 4: KHẢO SÁT CHỌN ĐỀ TÀI VÀ MỤC TIÊU DỰ ÁN
- **Khảo sát so sánh:** So sánh 6 đề tài trên thang 100 điểm với 6 tiêu chí khắt khe (Phù hợp môn học, Vừa sức, Chiều sâu mật mã, Khả năng Demo, Khả năng Viết Test, Chi phí 0 đồng).
- **Đề tài chiến thắng:** SecuDoc (100/100 điểm).
- **Mục tiêu chính:** Xây dựng hệ thống hoàn chỉnh cho phép cấp bằng, xác minh độc lập, phát hiện can thiệp và kiểm toán chuỗi nhật ký.
- **Chỉ số đo lường:** 100% phát hiện sai lệch nội dung; 100% chặn chữ ký giả mạo; thời gian xác minh < 100ms.

---

### SLIDE 5: MÔ HÌNH ĐE DỌA STRIDE VÀ RANH GIỚI TIN CẬY
- **Tài sản bảo vệ:** Khóa riêng RSA-2048, Tính toàn vẹn văn bản, Sổ cái băm bất biến, Tài khoản quản trị.
- **Tác nhân đe dọa:** Kẻ gian lận sửa điểm, kẻ mạo danh tự tạo khóa giả, kẻ tấn công DoS/Path Traversal, kẻ có đặc quyền nội bộ sửa lén Database.
- **Phân loại STRIDE:** Phân tích chi tiết 8 mối đe dọa (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) và giải pháp giảm thiểu tương ứng.

---

### SLIDE 6: KIẾN TRÚC HỆ THỐNG VÀ LUỒNG DỮ LIỆU
- **Kiến trúc 5 tầng:** UI/Client -> Web Service (Flask + Security Headers) -> Business Services (Auth, Doc, Verify, Audit) -> Core Crypto (RSA, SHA-256, Merkle) -> Safe Storage (SQLite, Isolated Vault).
- **Quy trình thẩm định 5 bước:** Băm tệp mới -> Đối soát DB -> Xác minh chữ ký bằng Public Key -> Tra cứu thu hồi -> Xuất phiếu chẩn đoán.

---

### SLIDE 7: CÁC CƠ CHẾ BẢO MẬT TRỌNG TÂM
- **Mã băm SHA-256:** Chuẩn FIPS 180-4, cơ chế Stream Chunking 64KB không tràn RAM, hiệu ứng tuyết lở (Avalanche Effect) đổi > 40% bits khi sửa 1 bit.
- **Chữ ký số RSA-2048:** Chuẩn PKCS#1 v1.5, kết hợp Khóa riêng bảo mật và Khóa công khai xuất khẩu để thẩm định offline.
- **Sổ cái băm liên hoàn (Hash Chain):** $H_i = \text{SHA256}(i \,||\, H_{i-1} \,||\, \text{Timestamp} \,||\, \text{Action} \,||\, \text{UUID} \,||\, \text{Hash})$. Ngăn chặn tuyệt đối việc sửa lén lịch sử.
- **PBKDF2-HMAC-SHA256:** 100,000 vòng lặp + salt ngẫu nhiên 16 bytes bảo vệ mật khẩu.

---

### SLIDE 8: HIỆN THỰC PROTOTYPE VÀ CÔNG NGHỆ
- **Tech Stack:** Python 3, Flask, Cryptography, SQLite, HTML5/CSS3/Vanilla JS (Cybersecurity Dark Theme).
- **Độc lập và tiện lợi:** Chạy 100% local trên Windows, không tốn phí bản quyền, không phụ thuộc dịch vụ ngoài.
- **Giao diện đa phân hệ:** Cổng thẩm định kéo thả công khai; Bảng điều khiển Issuer; Sổ cái kiểm toán viên; Phòng thí nghiệm Attack Lab tương tác; Công cụ dòng lệnh CLI.

---

### SLIDE 9: CÁC KỊCH BẢN TẤN CÔNG MÔ PHỎNG VÀ KẾT QUẢ
- **Kịch bản 1 (Sửa 1 byte):** GPA 2.50 đổi thành 3.90 -> Hệ thống phát hiện hash sai lệch (Avalanche 50%), lập tức báo `TAMPERED_CONTENT`.
- **Kịch bản 2 (Giả mạo chữ ký):** Kẻ tấn công sinh khóa RSA lạ và ký -> Root Public Key từ chối, báo `INVALID_SIGNATURE`.
- **Kịch bản 3 (Vượt rào thu hồi):** Bằng cấp bị thu hồi nhưng vẫn nộp -> Hệ thống phát hiện trạng thái `REVOKED`.
- **Kịch bản 4 (Sửa lén Database):** Đổi lén 1 ô trong SQLite -> Sổ cái báo đứt gãy chuỗi ngay tại Block bị sửa.
- **Kịch bản 5 (Path Traversal):** Tên file `../../evil.dll` -> Khử khuẩn an toàn và lưu dưới tên `{UUID}.bin`.

---

### SLIDE 10: KẾT QUẢ KIỂM THỬ THỰC NGHIỆM
- **Tổng số ca kiểm thử:** 25 / 25 Test Cases tự động.
- **Tỷ lệ thành công:** **100% PASS** (Thời gian chạy 3.88 giây trên Python unittest).
- **Độ bao phủ:** Unit test mật mã, integration test quy trình cấp/thu hồi, và manual attack scenarios.

---

### SLIDE 11: PHÂN TÍCH ĐÁNH ĐỔI (TRADE-OFF ANALYSIS)
- **Trade-off 1 (Kiểm soát toàn vẹn vs Quyền riêng tư):** Thẩm định dựa trên mã băm độc lập, không lưu tệp nhị phân của người thẩm định vào server -> Bảo vệ tuyệt đối quyền riêng tư cá nhân (GDPR / Nghị định 13).
- **Trade-off 2 (Khắt khe nhị phân vs Trải nghiệm tiện lợi):** Kiên quyết từ chối tệp sai 1 byte để ngăn chặn mã độc polyglot và gian lận tinh vi.
- **Trade-off 3 (Sổ cái nội bộ vs Blockchain công khai):** Tốc độ phản hồi tức thì (<10ms), chi phí 0 đồng, độc lập hạ tầng trường học.

---

### SLIDE 12: HẠN CHẾ, HƯỚNG PHÁT TRIỂN VÀ KẾT LUẬN
- **Hạn chế:** Hệ thống bảo vệ tệp số, không thay thế việc kiểm tra thực địa nếu đối tượng tạo văn bản hoàn toàn mới ngoài đời.
- **Hướng phát triển:** Tích hợp chứng thực số PKI X.509 quốc gia; hỗ trợ ứng dụng di động quét mã QR chứa chữ ký số nén.
- **Kết luận:** Đồ án đã giải quyết trọn vẹn và mẫu mực bài toán bảo mật tài liệu số, minh chứng xuất sắc cho nguyên tắc *"Zero-Trust: Không bao giờ tin tưởng, luôn luôn xác minh."*
