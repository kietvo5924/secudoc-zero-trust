# KẾT QUẢ KIỂM THỬ THỰC TẾ (SYSTEM TEST RESULTS)
**Dự án:** SecuDoc — Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  
**Thời gian thực thi:** Tháng 10/2026  
**Lệnh thực thi kiểm thử:** `python -m unittest discover -s tests -p "test_*.py" -v`  
**Môi trường:** Windows 11, Python 3.14.4, SQLite 3, Cryptography 44+, Pillow 12+, Qrcode 7.4+, Pyzbar 0.1.9  

---

## 1. TỔNG HỢP KẾT QUẢ KIỂM THỬ (EXECUTIVE SUMMARY)

- **Tổng số Test Case:** **46 / 46**
- **Số lượng ĐẠT (PASS):** **46 (100.0%)**
- **Số lượng THẤT BẠI (FAIL):** **0 (0.0%)**
- **Số lượng LỖI (ERROR):** **0 (0.0%)**
- **Số lượng BỎ QUA (NOT RUN):** **0 (0.0%)**
- **Số lượng CẢNH BÁO RÒ RỈ TÀI NGUYÊN (ResourceWarning):** **0**
- **Thời gian thực thi toàn bộ:** **~8.9 giây**

```text
Ran 46 tests in 8.919s
OK
```

---

## 2. BẢNG CHI TIẾT 45 TEST CASES THEO MODULE

### 2.1. Module Mật Mã Học Cốt Lõi (`tests/test_crypto.py` — 13 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-CRYPTO-01** | Tính toán băm SHA-256 test vector rỗng và chuỗi chuẩn | Khớp chuẩn NIST/FIPS 180-4 | Trùng khớp 100% | **PASS** |
| **TC-CRYPTO-02** | Hiệu ứng tuyết lở (Avalanche Effect) khi đảo 1 bit | > 40% bits thay đổi | 128/256 bits đổi (50.00%) | **PASS** |
| **TC-CRYPTO-03** | Khởi tạo, lưu trữ và nạp cặp khóa RSA 2048-bit | Keys 2048-bit hợp lệ | 2048-bit PEM verified | **PASS** |
| **TC-CRYPTO-04** | Ký số RSA-PKCS#1 v1.5 và xác minh hợp lệ | Signature 512 hex, verify=True | Verify trả về `True` | **PASS** |
| **TC-CRYPTO-05** | Từ chối chữ ký nếu digest bị đổi 1 ký tự | Verify trả về `False` | Verify trả về `False` | **PASS** |
| **TC-CRYPTO-06** | Từ chối chữ ký nếu xác minh bằng khóa công khai lạ | Verify trả về `False` | Verify trả về `False` | **PASS** |
| **TC-CRYPTO-07** | Tính toán và xác thực chuỗi 3 khối Hash-Chain | `is_valid: True` | Chuỗi toàn vẹn, không gãy | **PASS** |
| **TC-CRYPTO-08** | Phát hiện can thiệp dữ liệu khối trong sổ cái băm | Báo vỡ tại Block 1 | `is_valid: False, broken_at: 1` | **PASS** |
| **TC-CRYPTO-09** | Tính toán 256 vector nhị phân cho Avalanche Heatmap | 256 phần tử 0/1 | Khớp chuẩn Hamming vector | **PASS** |
| **TC-CRYPTO-10** | Ký số Canonical Metadata Payload & chống sửa metadata | Sửa recipient/type -> False | Chữ ký vô hiệu hóa lập tức | **PASS** |
| **TC-CRYPTO-11** | KeyManager tự khôi phục public key và từ chối ghi đè | Tạo lại public key an toàn | Khôi phục public key chuẩn | **PASS** |
| **TC-CRYPTO-12** | Sinh mã QR chuẩn và giải mã thực nghiệm qua pyzbar | Trích xuất đúng URL xác minh | Pyzbar decode khớp 100% | **PASS** |
| **TC-CRYPTO-13** | Sổ cái phát hiện xóa khối giữa, đổi Genesis & Head Hash | Phát hiện mọi dị thường | Gãy tại khối xóa; head hash khớp | **PASS** |

### 2.2. Module Động Cơ Xác Minh Zero-Trust (`tests/test_verification.py` — 9 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-VERIFY-01** | Thẩm định tài liệu nguyên gốc (Happy Path) | `VERIFIED_AUTHENTIC` | `is_authentic: True`, status khớp | **PASS** |
| **TC-VERIFY-02** | Phát hiện can thiệp tệp bị sửa 1 byte nhị phân | `TAMPERED_CONTENT` | Cảnh báo sửa đổi nội dung | **PASS** |
| **TC-VERIFY-03** | Phát hiện tài liệu đã bị cơ quan cấp thu hồi | `REVOKED` | Trạng thái `REVOKED` kèm lý do | **PASS** |
| **TC-VERIFY-04** | Thẩm định tài liệu lạ không có trong hệ thống | `NOT_FOUND` | Trả về `NOT_FOUND` | **PASS** |
| **TC-VERIFY-05** | Phát hiện chữ ký bị sửa trực tiếp trong CSDL | `INVALID_SIGNATURE` | Chữ ký không hợp lệ | **PASS** |
| **TC-VERIFY-06** | Thẩm định qua mã băm Client-side SHA-256 (0 byte file upload) | `VERIFIED_AUTHENTIC` | Trả về `VERIFIED_AUTHENTIC` | **PASS** |
| **TC-VERIFY-07** | Phát hiện kẻ xấu sửa tên người nhận trong SQLite | `INVALID_SIGNATURE` | Chữ ký Canonical Payload vô hiệu | **PASS** |
| **TC-VERIFY-08** | Sửa `status='ACTIVE'` cho tệp đã thu hồi -> Xung đột sổ cái | `REVOCATION_CONFLICT` | Đối soát chéo phát hiện mâu thuẫn | **PASS** |
| **TC-VERIFY-09** | Sổ cái kiểm toán bị vỡ khối -> Từ chối chứng thực | `AUDIT_CHAIN_BROKEN` | Từ chối cấp chứng nhận | **PASS** |

### 2.3. Module Xác Thực & Phân Quyền (`tests/test_auth.py` — 5 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-AUTH-01** | Băm mật khẩu PBKDF2 (100k rounds, salt 16 bytes) | Mật khẩu đúng -> True, sai -> False | Trùng khớp tuyệt đối | **PASS** |
| **TC-AUTH-02** | Muối ngẫu nhiên làm mật khẩu giống nhau có hash khác nhau | Muối và hash khác biệt | Khác biệt 100% | **PASS** |
| **TC-AUTH-03** | Xác thực tài khoản demo (`issuer`, `auditor`) | Đăng nhập thành công đúng vai trò | Phân quyền chính xác | **PASS** |
| **TC-AUTH-04** | Giới hạn số lần thử và khóa tạm thời (Rate Limiting Lockout) | > 5 lần sai -> PermissionError | Khóa 300s, mở lại khi reset | **PASS** |
| **TC-AUTH-05** | Chế độ Production (`DEMO_MODE=False`) không seed tài khoản | Bảng users có 0 bản ghi | 0 demo users created | **PASS** |

### 2.4. Module Quản Lý Tài Liệu (`tests/test_document.py` — 5 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-DOC-01** | Khử khuẩn tên tệp chống Path Traversal (`../../etc/passwd`) | Loại bỏ ký tự điều hướng | Trả về `passwd.pdf` an toàn | **PASS** |
| **TC-DOC-02** | Từ chối phát hành tệp rỗng (0 bytes) | Ném ngoại lệ `ValueError` | `ValueError` kích hoạt thành công | **PASS** |
| **TC-DOC-03** | Phát hành văn bản, lưu file cô lập và ghi block sổ cái | Tạo document `ACTIVE`, block `ISSUE` | Bản ghi và block liên kết chuẩn | **PASS** |
| **TC-DOC-04** | Thu hồi văn bản, đổi trạng thái và ghi block `REVOKE` | Đổi trạng thái `REVOKED`, thêm block | Cập nhật sổ cái đồng bộ | **PASS** |
| **TC-DOC-05** | Ứng phó sự cố: Thu hồi khẩn cấp hàng loạt khi tài khoản Issuer bị chiếm quyền | Hủy toàn bộ văn bằng cấp lậu, đóng dấu sổ cái | Toàn bộ văn bằng chuyển `REVOKED` | **PASS** |

### 2.5. Module Kịch Bản Tấn Công & Phòng Thủ (`tests/test_attack_scenarios.py` — 7 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-ATTACK-01** | THR-02: Kẻ gian sửa điểm GPA từ 2.50 thành 3.90 | Phát hiện sai lệch SHA-256 | Báo `TAMPERED_CONTENT` | **PASS** |
| **TC-ATTACK-02** | THR-01: Kẻ mạo danh tự tạo khóa RSA ký bằng cấp | Bị Root Public Key từ chối | Chữ ký giả bị chặn 100% | **PASS** |
| **TC-ATTACK-03** | THR-07: Sửa lén bản ghi SQLite nội bộ | Sổ cái báo đứt gãy tại Block 1 | `is_valid: False, broken_at: 1` | **PASS** |
| **TC-ATTACK-04** | THR-08: Tải tệp tên `../../../../evil.dll` | Chuẩn hóa thành `evil.dll` | Không ghi đè ngoài thư mục | **PASS** |
| **TC-ATTACK-05** | THR-03: Vượt rào văn bản đã bị thu hồi | Bị chặn với trạng thái `REVOKED` | `status == "REVOKED"` | **PASS** |
| **TC-ATTACK-06** | Phục hồi khối tùy ý (index != 0) & Cô lập Sandbox DB | Hoàn nguyên đúng snapshot gốc | Khối 2 phục hồi; DB chính nguyên vẹn | **PASS** |
| **TC-ATTACK-07** | Tấn công tính toán lại toàn bộ sổ cái (Chain Recalculation) | Bị phát hiện bởi External Anchor Head | Neo đỉnh chuỗi phát hiện can thiệp | **PASS** |

### 2.6. Module An Ninh Web & Quyền Riêng Tư (`tests/test_web_security.py` — 7 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-WEB-01** | Chống Open Redirect: từ chối `//evil.com`, `http://evil.com` | Chuyển hướng an toàn `/dashboard` | Chặn đứng chuyển hướng ngoài | **PASS** |
| **TC-WEB-02** | Bắt buộc CSRF Token trên toàn bộ POST endpoint | Thiếu token -> HTTP 400 Bad Request | Chặn request thiếu CSRF | **PASS** |
| **TC-WEB-03** | Kiểm soát phân quyền RBAC đa vai trò (Unauth -> Login, Auditor -> 403) | Phân quyền chuẩn xác theo vai trò | HTTP 403 / 302 chính xác | **PASS** |
| **TC-WEB-04** | API `/api/verify-hash` thẩm định chỉ bằng SHA-256 | 0 byte file bytes truyền tải | Xác thực thành công `is_authentic` | **PASS** |
| **TC-WEB-05** | Che giấu dữ liệu cá nhân (PII Masking) trên trang chủ | Ẩn họ tên: `N*** V*** A***` | Không lộ họ tên đầy đủ ra ngoài | **PASS** |
| **TC-WEB-06** | Endpoint `/api/trust-info` công khai ranh giới & vân tay khóa | Hiển thị fingerprint & limitations | Minh bạch giới hạn prototype | **PASS** |
| **TC-WEB-07** | Cô lập hoàn toàn Attack Lab vào `ATTACK_SANDBOX_DB` | Runtime DB không bị suy chuyển | Sandbox bị sửa, Main DB nguyên vẹn | **PASS** |

---

## 3. KẾT LUẬN NGHIỆM THU

Bộ kiểm thử thực tế đạt tỷ lệ **46/46 PASS (100%)**, thời gian thực thi ~8.9 giây, hoàn toàn không có cảnh báo rò rỉ kết nối `ResourceWarning`. Kết quả này xác nhận hệ thống hoạt động ổn định, an toàn và sẵn sàng cho buổi bảo vệ đồ án trước hội đồng.
