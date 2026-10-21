# CƠ CHẾ BẢO MẬT VÀ PHÂN TÍCH ĐÁNH ĐỔI (SECURITY CONTROLS & TRADE-OFF ANALYSIS)
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  

---

## 1. CHI TIẾT CÁC CƠ CHẾ BẢO VỆ ĐƯỢC LỰA CHỌN

Hệ thống SecuDoc không áp dụng bừa bãi mọi công nghệ mật mã, mà lựa chọn chính xác các cơ chế giải quyết trực tiếp các nguy cơ đã xác định trong Mô hình đe dọa (Threat Model):

### 1.1. Mã Băm Mật Mã Học Phân Mảnh (Cryptographic Hashing - SHA-256)
- **Chuẩn áp dụng:** FIPS 180-4 Secure Hash Standard (SHA-256), tạo ra đầu ra 256 bits (64 ký tự Hexadecimal).
- **Lý do lựa chọn:** Không sử dụng MD5 hay SHA-1 vì đã bị bẻ gãy va chạm (Collision attacks). SHA-256 bảo đảm tính kháng tiền ảnh (Pre-image resistance) và kháng va chạm (Collision resistance) tuyệt đối ở thời điểm hiện tại.
- **Cơ chế Avalanche Effect (Hiệu ứng tuyết lở):** Khi chỉ thay đổi đúng 1 bit nhị phân trong tệp tài liệu dung lượng hàng Megabyte, giá trị mã băm SHA-256 đầu ra sẽ thay đổi trung bình 50% các bit, hoàn toàn khác biệt so với mã băm ban đầu.
- **Cơ chế Stream Chunking (64KB):** Đọc tệp nhị phân theo từng khối 65,536 bytes; giúp hệ thống có thể băm các tệp lớn một cách mượt mà mà không làm tràn bộ nhớ RAM của máy chủ.

### 1.2. Chữ Ký Số Bất Đối Xứng (Digital Signature - RSA-2048 PKCS#1 v1.5)
- **Chuẩn áp dụng:** PKCS#1 v1.5 with SHA-256 digest, độ dài khóa 2048-bit, số mũ $e = 65537$.
- **Tại sao chỉ dùng Hash là không đủ?** Nếu chỉ lưu hash, kẻ tấn công sửa file có thể tự tính lại hash mới và ghi đè vào hệ thống. Chữ ký số giải quyết bài toán **Nguồn gốc (Origin)** và **Chống chối bỏ (Non-repudiation)**: Chỉ duy nhất chủ sở hữu của Khóa Riêng (Private Key) mới có thể tạo ra chữ ký hợp lệ; trong khi bất kỳ ai có Khóa Công Khai (Public Key) cũng có thể thẩm định tính chính xác của chữ ký.
- **Bảo vệ khóa riêng:** Khóa riêng được cách ly trong phân vùng lưu trữ máy chủ (`data/keys/root_private.pem`), không bao giờ được truyền qua mạng hay nhúng vào client.

### 1.3. Sổ Cái Băm Bất Biến (Tamper-Evident Hash Chain Audit Ledger)
- **Nguyên lý:** Mô phỏng cấu trúc chuỗi khối (Blockchain ledger) trong kiến trúc nội bộ. Mỗi hành động phát hành (`ISSUE`) hoặc thu hồi (`REVOKE`) tạo ra một block $B_i$.
- **Cấu trúc liên kết:**
  $$\text{Block Hash } H_i = \text{SHA256}(i \,||\, H_{i-1} \,||\, \text{Timestamp} \,||\, \text{Action} \,||\, \text{DocUUID} \,||\, \text{PayloadHash})$$
- **Tính năng phát hiện can thiệp nội bộ:** Nếu quản trị viên biến chất sửa đổi trực tiếp dữ liệu trong bảng SQLite (ví dụ: đổi trạng thái của văn bản bị thu hồi thành hợp lệ), khi Auditor chạy hàm `verify_audit_chain()`, chuỗi liên kết sẽ bị đứt gãy ngay tại block đó, chỉ ra chính xác vị trí và thời điểm bị làm giả.

### 1.4. Băm Mật Khẩu An Toàn (PBKDF2-HMAC-SHA256)
- **Chuẩn áp dụng:** NIST SP 800-132 Password-Based Key Derivation Function 2.
- **Tham số:** 100,000 vòng lặp (iterations), kèm muối ngẫu nhiên (salt) 16 bytes bằng hàm `secrets.token_bytes(16)`.
- **Hiệu quả phòng thủ:** Chống lại hoàn toàn tấn công Bảng Cầu Vồng (Rainbow Table) và làm chậm đáng kể các cuộc tấn công vét cạn (Brute-force/Dictionary attack).

### 1.5. Kiểm Soát Phân Quyền Phía Máy Chủ (Server-Side RBAC)
- **Nguyên tắc đặc quyền tối thiểu (Least Privilege):** 
  - `PUBLIC_VERIFIER`: Chỉ có quyền gửi tệp để thẩm định và xem kết quả.
  - `ISSUER`: Có quyền tải tệp lên để ký số, phát hành và thu hồi văn bản của mình.
  - `AUDITOR`: Có quyền kiểm tra toàn vẹn sổ cái và tra cứu lịch sử kiểm toán.
- **Thực thi:** Không chỉ ẩn nút bấm trên giao diện HTML, mọi request nhạy cảm đều được chặn lại ở backend bằng Python Decorator `@require_role(...)`.

### 1.6. Khử Khuẩn Đầu Vào & Cách Ly Tệp Tải Lên (Input Sanitization & Storage Isolation)
- **Kiểm soát dung lượng:** Giới hạn 10MB tại tầng HTTP.
- **Kiểm tra phần mở rộng:** Chỉ chấp nhận `.pdf`, `.docx`, `.png`, `.jpg`.
- **Cách ly vị trí lưu trữ:** Tên tệp do người dùng đặt bị loại bỏ khỏi đường dẫn lưu trữ; tệp được lưu dưới tên mã hóa UUID ngẫu nhiên `data/uploads/{uuid}.bin`, triệt tiêu hoàn toàn nguy cơ Path Traversal (`../../etc/passwd`).

---

## 2. PHÂN TÍCH ĐÁNH ĐỔI BẮT BUỘC (TRADE-OFF ANALYSIS)

Đề bài yêu cầu phân tích sâu sắc ít nhất một trade-off cụ thể giữa an toàn, riêng tư, tiện lợi, chi phí và khả năng triển khai, xét cả ngắn hạn và dài hạn:

### Trade-off 1: Thẩm định Bằng Mã Băm Độc lập vs. Quyền Riêng tư Dữ liệu Cá nhân
- **Bối cảnh:** Trong các hệ thống cũ, để xác minh một bảng điểm, nhà tuyển dụng phải gửi cả bảng điểm (chứa tên, ngày sinh, địa chỉ, số CMND/CCCD, danh sách điểm các môn học) cho trường hoặc tải lên máy chủ trung gian. Điều này làm lộ toàn bộ dữ liệu cá nhân (PII) nhạy cảm.
- **Phương án SecuDoc lựa chọn:** **Thẩm định phân tán dựa trên Mã băm (Hash-Based Verification)**:
  - Người dùng có thể chỉ cần tính toán mã băm SHA-256 của tệp ngay tại máy cá nhân rồi gửi chuỗi 64 ký tự lên hệ thống để đối soát với chữ ký số.
  - Hoặc nếu tải tệp lên cổng kiểm tra, máy chủ chỉ tính toán mã băm trong bộ nhớ tạm (in-memory hash calculation) rồi hủy luồng dữ liệu ngay, không lưu trữ nội dung tệp của người thẩm định vào cơ sở dữ liệu.
- **Bất lợi ngắn hạn:** Người dùng không rành công nghệ có thể thấy bỡ ngỡ khi hệ thống yêu cầu cung cấp đúng tệp nhị phân gốc (chỉ cần đổi định dạng hoặc nén lại tệp là hash thay đổi).
- **Lợi ích dài hạn:** Tuân thủ nghiêm ngặt các quy định về bảo vệ dữ liệu cá nhân (GDPR / Nghị định 13/2023/NĐ-CP của Việt Nam). Máy chủ thẩm định không lưu trữ tệp tài liệu của bên thứ ba, loại bỏ hoàn toàn nguy cơ rò rỉ dữ liệu diện rộng (Mass Data Breach) khi máy chủ bị tấn công.

### Trade-off 2: Chiều Sâu Kiểm Soát Toàn Vẹn Từng Byte vs. Trải Nghiệm Tiện Lợi (Strict Cryptographic Strictness vs. User Convenience)
- **Bối cảnh:** Thuật toán mã băm SHA-256 có tính chất nhạy cảm cực cao (strict byte-level integrity). Nếu người dùng mở file PDF trên điện thoại rồi bấm lưu lại làm phần mềm điện thoại tự ý chèn thêm vài byte metadata cuối file (trailing metadata), mã băm sẽ thay đổi hoàn toàn và bị hệ thống báo `TAMPERED_CONTENT`.
- **Phương án SecuDoc lựa chọn:** Giữ vững nguyên tắc **An toàn tối đa (Security First)**, kiên quyết từ chối mọi tệp có dù chỉ 1 byte sai lệch so với bản phát hành gốc.
- **Lý do chọn:** Trong an toàn thông tin pháp lý và bằng cấp, sự khoan nhượng với sai lệch nhị phân là cửa ngõ cho các cuộc tấn công chèn mã độc (Polyglot file) hoặc tấn công sửa đổi số liệu tinh vi.
- **Cách giảm thiểu bất lợi:** Giao diện trả về thông báo lỗi cực kỳ trực quan và giải thích rõ ràng: Cung cấp mã băm kỳ vọng (Expected Hash) và mã băm thực tế tính được (Actual Computed Hash), hướng dẫn người dùng sử dụng tệp nguyên gốc được tải trực tiếp từ cổng sinh viên.

### Trade-off 3: Sổ Cái Băm Cục Bộ (Local Hash Chain) vs. Mạng Blockchain Công Khai
- **Bối cảnh:** Các giải pháp Blockchain công khai (Ethereum, Solana) cung cấp tính phi tập trung tuyệt đối nhưng đi kèm chi phí giao dịch (gas fee) đắt đỏ, độ trễ giao dịch cao (vài chục giây đến vài phút) và phụ thuộc vào kết nối Internet toàn cầu.
- **Phương án SecuDoc lựa chọn:** Xây dựng **Sổ cái băm mật mã học cục bộ (Cryptographic Hash-Chain Ledger)** tích hợp ngay trong kiến trúc ứng dụng.
- **Bất lợi ngắn hạn:** Tính phi tập trung không cao bằng mạng lưới hàng nghìn node công khai.
- **Lợi ích dài hạn:** Chi phí vận hành bằng 0 (Zero Cost), tốc độ phản hồi tức thì (<10ms), hoạt động hoàn hảo trong mạng nội bộ đại học (Intranet), bảo đảm an toàn dữ liệu và tính độc lập công nghệ.

---

## 3. NHỮNG GÌ CƠ CHẾ NÀY BẢO VỆ VÀ KHÔNG BẢO VỆ

| Cơ Chế | Những Gì BẢO VỆ ĐƯỢC | Những Gì KHÔNG BẢO VỆ ĐƯỢC |
|:---|:---|:---|
| **SHA-256 + RSA-2048** | Phát hiện 100% việc sửa đổi nội dung tệp; chứng minh chắc chắn văn bản do cơ quan nắm khóa riêng phát hành. | Không ngăn chặn được việc cơ quan phát hành ban đầu nhập sai dữ liệu của sinh viên trước khi ký số (Garbage In, Garbage Out). |
| **Sổ Cái Băm Hash Chain** | Phát hiện 100% các hành vi sửa lén, xóa hoặc chèn bản ghi vào cơ sở dữ liệu lịch sử. | Không ngăn chặn được kẻ có quyền root trên hệ điều hành xóa sạch toàn bộ file cơ sở dữ liệu và file khóa (cần cơ chế sao lưu định kỳ ngoài hệ thống). |
| **PBKDF2 + Role Decorators** | Chặn kẻ tấn công dò quét mật khẩu và chặn người dùng thường gọi các API quản trị. | Không bảo vệ được nếu quản trị viên tự nguyện chia sẻ mật khẩu của mình cho người ngoài hoặc máy tính của quản trị viên bị nhiễm mã độc Keylogger. |
