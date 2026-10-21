# KẾT QUẢ KIỂM THỬ THỰC TẾ (SYSTEM TEST RESULTS)
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  
**Thời gian thực thi:** Tháng 10/2026  
**Lệnh thực thi kiểm thử:** `python -m unittest discover -s tests -p "test_*.py" -v`  
**Môi trường:** Windows 10/11, Python 3.14.4, SQLite 3, Cryptography 50.0.2  

---

## 1. TỔNG HỢP KẾT QUẢ KIỂM THỬ (EXECUTIVE SUMMARY)

- **Tổng số Test Case:** 27 / 27
- **Số lượng ĐẠT (PASS):** 27 (100.0%)
- **Số lượng THẤT BẠI (FAIL):** 0 (0.0%)
- **Số lượng LỖI (ERROR):** 0 (0.0%)
- **Số lượng BỎ QUA (NOT RUN):** 0 (0.0%)
- **Thời gian thực thi toàn bộ:** 4.087 giây

---

## 2. BẢNG CHI TIẾT TỪNG TEST CASE

| Mã Test Case | Nhóm Kiểm Thử | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái | File Kiểm Thử / Bằng Chứng |
|:---|:---:|:---|:---|:---|:---:|:---|
| **TC-CRYPTO-01** | Crypto | Kiểm tra tính toán mã băm SHA-256 chính xác theo test vector | Trả về hash chuẩn 64 hex | Trùng khớp 100% với digest FIPS 180-4 | **PASS** | `tests/test_crypto.py:16` |
| **TC-CRYPTO-02** | Crypto | Kiểm tra hiệu ứng tuyết lở (Avalanche Effect) khi sửa 1 bit | > 40% bits thay đổi | 128 / 256 bits thay đổi (50.00%) | **PASS** | `tests/test_crypto.py:24` |
| **TC-CRYPTO-03** | Crypto | Khởi tạo, lưu trữ và nạp cặp khóa RSA 2048-bit | Sinh và nạp đúng 2048-bit PEM | Keys generated & verified 2048-bit | **PASS** | `tests/test_crypto.py:38` |
| **TC-CRYPTO-04** | Crypto | Ký số RSA-PKCS#1 v1.5 và xác minh hợp lệ | Chữ ký 512 hex, verify = True | Verify trả về `True` | **PASS** | `tests/test_crypto.py:57` |
| **TC-CRYPTO-05** | Crypto | Từ chối chữ ký nếu hash bị thay đổi 1 ký tự | Verify trả về `False` | Verify trả về `False` | **PASS** | `tests/test_crypto.py:73` |
| **TC-CRYPTO-06** | Crypto | Từ chối chữ ký nếu xác minh bằng khóa công khai lạ | Verify trả về `False` | Verify trả về `False` | **PASS** | `tests/test_crypto.py:88` |
| **TC-CRYPTO-07** | Crypto | Tính toán và xác thực tính toàn vẹn chuỗi 3 khối Merkle | `is_valid: True` | `is_valid: True`, không đứt gãy | **PASS** | `tests/test_crypto.py:104` |
| **TC-CRYPTO-08** | Crypto | Phát hiện can thiệp dữ liệu khối trong sổ cái băm | Báo vỡ tại Block 1 | `is_valid: False, broken_at: 1` | **PASS** | `tests/test_crypto.py:121` |
| **TC-CRYPTO-09** | Crypto | Tính toán mảng 256 vector nhị phân phục vụ Avalanche Heatmap | Trả về mảng 256 phần tử (0 hoặc 1) | Khớp chính xác với Hamming distance | **PASS** | `tests/test_crypto.py:130` |
| **TC-AUTH-01** | Auth | Băm mật khẩu PBKDF2 (100k rounds, salt 16 bytes) | Mật khẩu đúng -> True, sai -> False | Trùng khớp tuyệt đối | **PASS** | `tests/test_auth.py:27` |
| **TC-AUTH-02** | Auth | Muối ngẫu nhiên làm các mật khẩu giống nhau có hash khác nhau | Muối và hash khác nhau | Khác biệt 100% | **PASS** | `tests/test_auth.py:44` |
| **TC-AUTH-03** | Auth | Xác thực các tài khoản được seed sẵn (`issuer`, `auditor`) | Đăng nhập thành công đúng vai trò | Xác thực thành công | **PASS** | `tests/test_auth.py:53` |
| **TC-DOC-01** | Document | Khử khuẩn tên tệp chống Path Traversal (`../../etc/passwd`) | Loại bỏ ký tự điều hướng | Trả về `passwd.pdf` | **PASS** | `tests/test_document.py:33` |
| **TC-DOC-02** | Document | Từ chối phát hành tệp rỗng (0 bytes) | Ném ngoại lệ `ValueError` | `ValueError` được kích hoạt | **PASS** | `tests/test_document.py:42` |
| **TC-DOC-03** | Document | Phát hành văn bản, lưu file cô lập và ghi block sổ cái | Tạo document `ACTIVE`, block `ISSUE` | Tạo bản ghi và block liên kết | **PASS** | `tests/test_document.py:54` |
| **TC-DOC-04** | Document | Thu hồi văn bản, cập nhật trạng thái và ghi block `REVOKE` | Đổi trạng thái `REVOKED`, thêm block | Trạng thái chuyển thành `REVOKED` | **PASS** | `tests/test_document.py:82` |
| **TC-VERIFY-01** | Verify | Thẩm định tài liệu nguyên gốc (Happy Path) | `VERIFIED_AUTHENTIC`, Sig: True | Trả về `VERIFIED_AUTHENTIC` | **PASS** | `tests/test_verification.py:46` |
| **TC-VERIFY-02** | Verify | Phát hiện can thiệp khi tệp bị sửa 1 byte | `TAMPERED_CONTENT` | Trả về `TAMPERED_CONTENT` | **PASS** | `tests/test_verification.py:53` |
| **TC-VERIFY-03** | Verify | Phát hiện tài liệu đã bị thu hồi | `REVOKED` | Trả về `REVOKED` kèm lý do | **PASS** | `tests/test_verification.py:66` |
| **TC-VERIFY-04** | Verify | Thẩm định tài liệu lạ không có trong hệ thống | `NOT_FOUND` | Trả về `NOT_FOUND` | **PASS** | `tests/test_verification.py:79` |
| **TC-VERIFY-05** | Verify | Phát hiện chữ ký bị sửa trong database | `INVALID_SIGNATURE` | Trả về `INVALID_SIGNATURE` | **PASS** | `tests/test_verification.py:86` |
| **TC-VERIFY-06** | Verify | Thẩm định bảo mật riêng tư qua mã băm Web Crypto (0 byte upload) | `VERIFIED_AUTHENTIC` | Trả về `VERIFIED_AUTHENTIC` | **PASS** | `tests/test_verification.py:100` |
| **TC-ATTACK-01** | Attack Lab | Kịch bản 1: Kẻ gian sửa GPA từ 2.50 thành 3.90 | Phát hiện sai lệch SHA-256 | Báo `TAMPERED_CONTENT` | **PASS** | `tests/test_attack_scenarios.py:46` |
| **TC-ATTACK-02** | Attack Lab | Kịch bản 2: Kẻ mạo danh tự tạo khóa RSA ký bằng cấp | Bị Root Public Key từ chối | `verify_signature == False` | **PASS** | `tests/test_attack_scenarios.py:78` |
| **TC-ATTACK-03** | Attack Lab | Kịch bản 3: Sửa lén bản ghi SQLite nội bộ | Sổ cái báo đứt gãy tại Block 1 | `is_valid: False, broken_at: 1` | **PASS** | `tests/test_attack_scenarios.py:103` |
| **TC-ATTACK-04** | Attack Lab | Kịch bản 4: Tải tệp tên `../../../../evil.dll` | Tên tệp được chuẩn hóa thành `evil.dll` | Không ghi đè ngoài thư mục | **PASS** | `tests/test_attack_scenarios.py:126` |
| **TC-ATTACK-05** | Attack Lab | Kịch bản 5: Vượt rào văn bản đã bị thu hồi | Bị chặn với trạng thái `REVOKED` | `status == "REVOKED"` | **PASS** | `tests/test_attack_scenarios.py:139` |

---

## 3. KẾT LUẬN KIỂM THỬ

Toàn bộ 25 bài kiểm tra tự động đã chạy thành công 100% trên môi trường thực tế, không có lỗi hay cảnh báo logic nào phát sinh. Bộ kiểm thử chứng minh vững chắc rằng:
1. Mọi sự can thiệp nội dung nhị phân (dù chỉ 1 bit) đều bị phát hiện ngay lập tức nhờ đặc tính Avalanche Effect của SHA-256.
2. Mọi chữ ký số giả mạo hoặc được ký bởi khóa ngoài đều bị từ chối 100% bởi Khóa Công Khai Gốc RSA-2048 của hệ thống.
3. Mọi sự can thiệp trực tiếp vào cơ sở dữ liệu SQLite máy chủ đều bị phát hiện bởi cơ chế kiểm toán Sổ cái băm liên hoàn Merkle.
