# BÁO CÁO TỔNG KẾT ĐỒ ÁN CUỐI KỲ
**Học phần:** Bảo Mật Mạng Máy Tính và Hệ Thống  
**Tên đề tài:** SecuDoc - Hệ thống Xác minh Chứng thực Văn bản Số Chống Giả mạo với Chuỗi Nhật ký Bất biến  
**Phiên bản:** 1.0.0 (Tháng 10/2026)  
**Nhóm sinh viên thực hiện:** [Để trống để sinh viên điền thông tin]  
**Giảng viên hướng dẫn:** [Để trống để sinh viên điền thông tin]  

---

## TÓM TẮT ĐỒ ÁN (ABSTRACT)
Đồ án **SecuDoc** được thiết kế và hiện thực hóa dựa trên nguyên tắc an ninh cốt lõi: *"Không phải mọi thông tin mà hệ thống nhận được đều đáng tin cậy. Tuyệt đối không mặc định tin tưởng đầu vào chỉ vì nó trông có vẻ thật."*

Hệ thống giải quyết triệt để vấn nạn làm giả bảng điểm, chứng chỉ và bằng đại học điện tử bằng cách áp dụng kiến trúc **Zero-Trust** kết hợp 3 trụ cột mật mã học vững chắc:
1. **Mã băm phân mảnh SHA-256 (FIPS 180-4):** Đọc tệp nhị phân theo luồng stream 64KB, kiểm soát tính toàn vẹn tới từng bit dữ liệu với hiệu ứng tuyết lở (Avalanche Effect > 50%).
2. **Chữ ký số bất đối xứng RSA-2048 PKCS#1 v1.5:** Sử dụng Khóa riêng của Trường Đại học để ký số lên mã băm; bảo đảm tính xác thực nguồn gốc và chống chối bỏ (Non-repudiation).
3. **Sổ cái băm mật mã liên hoàn (Merkle / Hash-Chain Ledger):** Liên kết lịch sử phát hành và thu hồi chứng chỉ qua chuỗi $H_i = \text{SHA256}(i \,||\, H_{i-1} \,||\, \text{Timestamp} \,||\, \text{Action} \,||\, \text{UUID} \,||\, \text{PayloadHash})$, ngăn chặn mọi hành vi can thiệp lén cơ sở dữ liệu nội bộ.

Hệ thống được lập trình hoàn chỉnh bằng Python 3, Flask, Cryptography, SQLite và giao diện Web hiện đại (Cybersecurity Dark Theme), đạt tỷ lệ **100% PASS trên toàn bộ 46 bài kiểm thử tự động**, tích hợp sẵn phòng thí nghiệm mô phỏng tấn công (Attack Lab) và công cụ dòng lệnh (CLI Utility).

---

## 1. BỐI CẢNH VÀ ĐẶT VẤN ĐỀ THỰC TẾ
Trong thời đại chuyển đổi số giáo dục và tuyển dụng trực tuyến, hàng triệu văn bản hành chính, bằng cử nhân, bảng điểm và hợp đồng số được phát hành dưới dạng tệp điện tử (PDF, DOCX). Tuy nhiên, các định dạng này rất dễ bị chỉnh sửa bằng phần mềm đồ họa chỉ trong vài phút. 

### Các Lỗ Hổng Cốt Lõi của Cách Làm Truyền Thống:
- Mắt thường không thể phân biệt tệp PDF nguyên bản và tệp đã bị sửa đổi điểm số (GPA 2.50 thành 3.90).
- Con dấu scanned hoặc logo hình ảnh dễ dàng bị sao chép hoặc cắt dán.
- Thiếu cơ chế đối soát tức thì khi một văn bản đã bị thu hồi do kỷ luật hoặc gian lận thi cử.

---

## 2. ĐỐI TƯỢNG SỬ DỤNG VÀ PHÂN TÍCH TÀI SẢN BẢO VỆ
1. **Người Phát Hành (Issuer - Phòng Đào Tạo):** Tải văn bản gốc lên, tạo chữ ký số RSA-2048, lưu trữ tệp cô lập và đóng block vào sổ cái. Có quyền thu hồi văn bản khi có quyết định kỷ luật.
2. **Người Thẩm Định Độc Lập (Verifier - Nhà Tuyển Dụng / Bên Thứ Ba):** Tải tệp nhận được lên cổng kiểm tra để đối soát toán học mà không cần tài khoản.
3. **Kiểm Toán Viên An Ninh (Auditor):** Chạy tiến trình quét toán học toàn bộ chuỗi băm để kiểm tra tính toàn vẹn của sổ cái lưu trữ.

---

## 3. MÔ HÌNH ĐE DỌA STRIDE VÀ MA TRẬN PHÒNG THỦ
Hệ thống xác định 5 nhóm mối đe dọa trọng tâm:
- **THR-01 (Spoofing):** Kẻ tấn công tự tạo khóa ký giả mạo của trường -> *Phòng thủ:* Root Public Key chính thức của trường từ chối xác minh (`INVALID_SIGNATURE`).
- **THR-02 (Tampering):** Kẻ gian sửa 1 ký tự điểm GPA trong file PDF -> *Phòng thủ:* SHA-256 Stream Hashing phát hiện sai lệch và báo `TAMPERED_CONTENT`.
- **THR-03 (Repudiation):** Cơ quan phát hành chối bỏ việc đã cấp bằng -> *Phòng thủ:* Chữ ký số RSA-2048 PKCS#1 v1.5 mang giá trị pháp lý không thể chối bỏ.
- **THR-07 (Tampering DB):** Kẻ gian nội bộ sửa trực tiếp ô dữ liệu trong SQLite -> *Phòng thủ:* Sổ cái băm Merkle phát hiện đứt gãy chuỗi ngay tại block bị sửa.
- **THR-08 (Injection / Path Traversal):** Tải file có tên `../../evil.dll` -> *Phòng thủ:* Hàm `sanitize_filename()` bóc tách an toàn và lưu trữ dưới dạng cô lập `{UUID}.bin`.

### 3.1. Kịch Bản Ứng Phó Khi Tài Khoản Bị Chiếm Quyền (Compromised Account Protocol)
Để trả lời câu hỏi cốt lõi của đề tài: *"Nếu tài khoản bị chiếm quyền thì hệ thống xử lý như thế nào?"*, SecuDoc thiết lập quy trình phản ứng sự cố 4 lớp (Defense-in-Depth Incident Response):
1. **Khóa tài khoản tự động (Account Lockout):** Cơ chế Rate Limiting phát hiện dò quét mật khẩu và khóa tài khoản tức thì sau 5 lần thất bại liên tiếp trong 300 giây.
2. **Bảo toàn bằng chứng bất biến (Immutable Audit Trail):** Kể cả khi kẻ tấn công có được mật khẩu Issuer để cấp bằng khống, kẻ đó **hoàn toàn không thể xóa dấu vết hoặc sửa đổi các khối đã cấp trước đó** nhờ cấu trúc chuỗi khối liên kết toán học SHA-256 (`prev_block_hash`). Mọi hành vi trái phép đều bị ghi nhận vĩnh viễn trên sổ cái.
3. **Lệnh thu hồi khẩn cấp hàng loạt (`emergency_batch_revoke`):** Quản trị viên/Auditor có thể kích hoạt lệnh thu hồi toàn bộ các văn bằng được phát hành trong khoảng thời gian tài khoản Issuer bị chiếm quyền. Mỗi lệnh thu hồi tạo một khối `REVOKE` mới đóng dấu vào sổ cái, khiến cổng thẩm định Zero-Trust lập tức chuyển trạng thái sang `REVOKED`.
4. **Định hướng kiểm soát kép (Dual-Approval / Maker-Checker):** Kiến trúc sẵn sàng tích hợp quy trình phê duyệt 2 bước: Một tài khoản tạo văn bản (Maker) và một lãnh đạo ký duyệt (Checker) thì văn bằng mới được ký số và vào sổ cái.

---

## 4. KIẾN TRÚC HỆ THỐNG VÀ LUỒNG DỮ LIỆU
Hệ thống triển khai mô hình 5 tầng:
1. **Tầng Trình Diễn (UI):** Cổng Thẩm định kéo thả, Bảng điều khiển Issuer, Sổ cái Auditor, Phòng Thí nghiệm Attack Lab.
2. **Tầng Dịch Vụ Web (Flask):** Middleware an toàn (CSP, X-Frame-Options, Nosniff), Input Sanitizer, Decorator RBAC `@require_role`.
3. **Tầng Nghiệp Vụ (Services):** `AuthService`, `DocumentService`, `VerificationEngine`, `AuditService`.
4. **Tầng Động Cơ Mật Mã (Crypto Engine):** `KeyManager` (RSA-2048), `HashingEngine` (SHA-256), `SignatureEngine`, `MerkleEngine`.
5. **Tầng Lưu Trữ (Storage):** SQLite (`secudoc.db`), Thư mục khóa (`data/keys/`), Kho tệp cô lập (`data/uploads/`).

---

## 5. THỰC NGHIỆM TẤN CÔNG (ATTACK LAB SIMULATION)
Phòng thí nghiệm tích hợp sẵn trên giao diện web chứng minh thực nghiệm 5 kịch bản tấn công:
1. **Tấn công đảo 1 bit (Bit-Flip Tampering):** Thay đổi đúng 1 bit ở byte đầu tiên -> Hiệu ứng tuyết lở làm đổi 128 / 256 bits SHA-256 (50.00%); Hệ thống lập tức trả về thẻ đỏ `TAMPERED_CONTENT`.
2. **Tấn công giả mạo chữ ký (Rogue Key Forgery):** Kẻ mạo danh tự sinh khóa RSA riêng và ký -> Khóa công khai của trường từ chối xác minh; hệ thống báo lỗi `INVALID_SIGNATURE`.
3. **Tấn công vượt rào văn bản thu hồi (Revocation Bypass):** Thẩm định văn bản đã bị thu hồi -> Trả về cảnh báo màu vàng `REVOKED` kèm lý do kỷ luật.
4. **Tấn công sửa lén Database:** Can thiệp sửa 1 ô dữ liệu trong SQLite -> Hàm kiểm toán sổ cái báo vỡ chuỗi tại chính xác Block bị sửa.
5. **Tấn công Path Traversal:** Gửi tên tệp `../../evil.dll` -> Hệ thống khử khuẩn và lưu an toàn thành `evil.dll`.

---

## 6. KẾT QUẢ KIỂM THỬ THỰC TẾ (46/46 PASS 100%)
Toàn bộ 46 bài kiểm thử tự động đã thực thi thành công 100% trên môi trường Windows thông qua lệnh:
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```
- **Thời gian chạy:** ~8.9 giây.
- **Tỷ lệ:** 46/46 Test Cases PASS (0 Failures, 0 Errors, 100% Passed).
- **Chi tiết kết quả:** Được ghi nhận đầy đủ trong `docs/TEST_RESULTS.md`.

---

## 7. PHÂN TÍCH ĐÁNH ĐỔI BẮT BUỘC (TRADE-OFF ANALYSIS: NGẮN HẠN VS DÀI HẠN)
1. **Đánh đổi Toàn vẹn vs Quyền riêng tư (Privacy vs Integrity):**
   - *Ngắn hạn:* Thẩm định dựa trên mã băm độc lập, không lưu trữ tệp của người thẩm định vào cơ sở dữ liệu -> Tuân thủ 100% luật bảo vệ dữ liệu cá nhân (GDPR và Nghị định 13/2023/NĐ-CP).
   - *Dài hạn:* Hỗ trợ Web Crypto API băm tại trình duyệt client, máy chủ không bao giờ nhìn thấy nội dung file thô, giảm thiểu tối đa trách nhiệm pháp lý khi lưu trữ PII.
2. **Đánh đổi Khắt khe Nhị phân vs Tiện lợi Người dùng (Strictness vs Usability):**
   - *Ngắn hạn:* Kiên quyết từ chối mọi tệp sai lệch 1 byte để ngăn chặn mã độc polyglot và gian lận tinh vi.
   - *Dài hạn:* Đánh đổi này có thể gây bất tiện nếu phần mềm PDF của người dùng tự động cập nhật metadata ngày mở. Hướng mở rộng dài hạn là áp dụng chuẩn chữ ký số nhúng **PAdES (PDF Advanced Electronic Signatures)** để bảo vệ trường nội dung độc lập với metadata vô hại.
3. **Đánh đổi Sổ cái Cục bộ vs Blockchain Công khai (Local Hash-Chain vs Public/Consortium Blockchain):**
   - *Ngắn hạn:* Sổ cái băm nội bộ (SQLite Hash-Chain) đem lại chi phí vận hành bằng 0 đồng, tốc độ <10ms và tính độc lập hoàn toàn trong mạng nội bộ đại học, không tốn phí gas.
   - *Dài hạn:* Chấp nhận rủi ro Single Point of Failure nếu máy chủ trường bị phá hủy vật lý. Trong dài hạn, cần mở rộng sang mạng lưới **Consortium Blockchain liên trường** để phân tán quyền kiểm chứng mà vẫn giữ vững chi phí thấp.

---

## 8. HẠN CHẾ VÀ HƯỚNG PHÁT TRIỂN
- **Hạn chế:** Hệ thống bảo vệ tệp số, chưa thay thế việc điều tra thực địa ngoài đời nếu kẻ gian tạo văn bản mới hoàn toàn từ đầu.
- **Hướng phát triển:** Tích hợp chữ ký số công cộng PKI X.509 quốc gia; hỗ trợ ứng dụng di động quét mã QR chứa chữ ký nén để thẩm định offline hoàn toàn.

---

## 9. TÀI LIỆU THAM KHẢO
1. NIST Special Publication 800-132, "Recommendation for Password-Based Key Derivation: Part 1 - Storage Applications", 2010.
2. FIPS PUB 180-4, "Secure Hash Standard (SHS)", National Institute of Standards and Technology, 2015.
3. RFC 8017, "PKCS #1: RSA Cryptography Specifications Version 2.2", IETF, 2016.
4. RFC 6962, "Certificate Transparency", IETF, 2013.
5. Nghị định 13/2023/NĐ-CP của Chính phủ về Bảo vệ Dữ liệu Cá nhân, 2023.
