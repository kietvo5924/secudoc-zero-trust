# KẾ HOẠCH KIỂM THỬ HỆ THỐNG (SYSTEM TEST PLAN)
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  

---

## 1. MỤC TIÊU VÀ CHIẾN LƯỢC KIỂM THỬ

Kế hoạch kiểm thử nhằm chứng minh tính đúng đắn của logic nghiệp vụ thông thường (Happy Path) và kiểm chứng năng lực phòng thủ của hệ thống trước các kịch bản tấn công giả mạo, can thiệp dữ liệu, xâm phạm quyền hạn và sửa đổi trái phép cơ sở dữ liệu.

### Chiến lược Kiểm thử 3 Tầng:
1. **Kiểm thử Đơn vị (Unit Tests):** Kiểm tra độc lập từng hàm mật mã (SHA-256 stream, RSA key generation, RSA sign/verify, PBKDF2 hash, Merkle/Hash Chain computation).
2. **Kiểm thử Tích hợp (Integration Tests):** Kiểm tra luồng liên kết end-to-end từ Tải tệp -> Tính băm -> Ký số -> Ghi sổ cái -> Thẩm định thành công.
3. **Kiểm thử Tấn công Bảo mật (Security & Attack Simulation Tests):** Tự động mô phỏng các hành vi xâm phạm thực tế:
   - Tấn công đổi 1 bit/byte trong file (Bit-flip Tampering Attack).
   - Tấn công giả mạo chữ ký bằng khóa riêng không hợp lệ (Signature Forgery Attack).
   - Tấn công sử dụng chứng chỉ đã bị thu hồi (Revocation Bypass Attack).
   - Tấn công sửa đổi trực tiếp dữ liệu trong bảng SQLite (Database Ledger Tampering Attack).
   - Tấn công vượt quyền hạn (Unauthorized Role Access).
   - Tấn công vượt ngưỡng kích thước tệp và tấn công Path Traversal.

---

## 2. MA TRẬN TEST CASE CHI TIẾT

| Mã Test | Phân Loại | Mục Tiêu Kiểm Thử | Điều Kiện Tiên Quyết | Dữ Liệu Đầu Vào | Các Bước Thực Hiện | Kết Quả Mong Đợi |
|:---|:---:|:---|:---|:---|:---|:---|
| **TC-CRYPTO-01** | Unit (Crypto) | Kiểm tra tính toán mã băm SHA-256 chính xác | Động cơ băm khởi tạo | Chuỗi byte mẫu đã biết trước hash chuẩn | Gọi hàm `calculate_bytes_hash()` | Trả về chuỗi 64 ký tự hex khớp 100% với giá trị SHA-256 chuẩn |
| **TC-CRYPTO-02** | Unit (Crypto) | Kiểm tra hiệu ứng tuyết lở (Avalanche Effect) của SHA-256 | Động cơ băm khởi tạo | File gốc và file bị sửa đúng 1 bit nhị phân | Tính hash 2 file và so sánh khoảng cách Hamming | Hai mã hash khác biệt > 40% số bit |
| **TC-CRYPTO-03** | Unit (Crypto) | Ký số và xác minh chữ ký RSA-2048 thành công | Cặp khóa RSA chính thức | File hash đại diện | 1. Gọi `sign_hash(private_key)`<br>2. Gọi `verify_signature(public_key)` | Hàm xác minh trả về `True` |
| **TC-CRYPTO-04** | Unit (Crypto) | Chữ ký số bị từ chối nếu dữ liệu bị sửa đổi | Cặp khóa RSA chính thức | File hash gốc đã ký | 1. Thay đổi 1 ký tự trong hash<br>2. Gọi `verify_signature()` | Hàm xác minh trả về `False` |
| **TC-CRYPTO-05** | Unit (Crypto) | Tính toán và xác minh khối sổ cái băm liên hoàn | Cấu trúc AuditBlock | 3 block dữ liệu liên tiếp | 1. Tạo block 0, 1, 2<br>2. Gọi `verify_audit_chain()` | Hàm xác minh chuỗi trả về `is_valid: True` |
| **TC-AUTH-01** | Unit (Auth) | Băm mật khẩu và đối soát PBKDF2 an toàn | Auth service sẵn sàng | Password: `SecretPass123!` | 1. Gọi `hash_password()`<br>2. Gọi `verify_password()` | Password đúng trả về `True`; password sai trả về `False` |
| **TC-AUTH-02** | Unit (Auth) | Phân quyền RBAC chặn người dùng trái phép | Người dùng có vai trò `PUBLIC_VERIFIER` | Request gọi API phát hành `/api/issue` | Gửi request không có quyền `ISSUER` | Trả về mã lỗi HTTP 403 Forbidden |
| **TC-DOC-01** | Integration | Phát hành văn bản và đóng block sổ cái thành công | Đăng nhập tài khoản `issuer` | Tệp `bang_diem_sv.pdf` hợp lệ | Gọi hàm phát hành văn bản | Tạo bản ghi tài liệu `ACTIVE`, sinh chữ ký số, và tạo 1 block mới trong sổ cái |
| **TC-DOC-02** | Integration | Thu hồi văn bản hợp lệ | Văn bản đã phát hành ở trạng thái `ACTIVE` | `doc_uuid` và lý do thu hồi | Gọi hàm thu hồi `revoke_document()` | Trạng thái chuyển thành `REVOKED`, tạo thêm block `REVOKE` trong sổ cái |
| **TC-VERIFY-01** | Integration | Thẩm định tài liệu nguyên gốc (Happy Path) | Văn bản đã phát hành | Đúng tệp gốc ban đầu | Gửi tệp đến động cơ thẩm định | Trả về trạng thái `VERIFIED_AUTHENTIC`, chữ ký hợp lệ, thông tin cơ quan cấp |
| **TC-SEC-01** | Attack Test | Mô phỏng tấn công sửa 1 byte trong tệp (Tampering) | Văn bản đã phát hành | Tệp gốc bị đảo 1 byte tại vị trí ngẫu nhiên | Gửi tệp đã sửa đến động cơ thẩm định | Trả về trạng thái `TAMPERED_CONTENT` hoặc `NOT_FOUND`, cảnh báo can thiệp dữ liệu |
| **TC-SEC-02** | Attack Test | Mô phỏng tấn công giả mạo chữ ký (Key Forgery) | Tệp văn bản mẫu | Chữ ký được sinh bởi một cặp khóa RSA khác | Gửi tệp kèm chữ ký giả để thẩm tra | Trả về trạng thái `INVALID_SIGNATURE`, từ chối chứng thực |
| **TC-SEC-03** | Attack Test | Mô phỏng thẩm định tài liệu đã bị thu hồi | Văn bản đã bị thu hồi (`REVOKED`) | Tệp văn bản gốc | Gửi tệp đến động cơ thẩm định | Trả về trạng thái `REVOKED`, hiển thị lý do và thời gian thu hồi |
| **TC-SEC-04** | Attack Test | Mô phỏng sửa lén cơ sở dữ liệu (Database Tampering) | Sổ cái đang chứa 3 block hợp lệ | Can thiệp SQLite sửa dữ liệu block 1 | Chạy tiến trình kiểm toán `verify_audit_chain()` | Trả về `is_valid: False`, báo vỡ chuỗi tại `broken_at_block_index = 1` |
| **TC-SEC-05** | Security | Ngăn chặn tấn công Path Traversal khi tải tệp | Web server hoạt động | Tên tệp: `../../evil.exe` | Gửi form tải tệp với filename độc hại | Hệ thống lọc sạch tên tệp, lưu trữ an toàn dưới mã UUID cô lập |
| **TC-SEC-06** | Security | Giới hạn dung lượng tệp tải lên (Payload Size Guard) | Web server hoạt động | Tệp dung lượng 15MB (> 10MB) | Gửi tệp quá cỡ lên máy chủ | Trả về mã lỗi HTTP 413 Payload Too Large, server không bị crash |

---

## 3. LỆNH THỰC THI KIỂM THỬ

Toàn bộ bộ kiểm thử được chạy tự động thông qua Python Standard `unittest`:
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Kết quả thực tế sau khi chạy sẽ được trích xuất và lưu trữ chi tiết trong tài liệu `docs/TEST_RESULTS.md`.
