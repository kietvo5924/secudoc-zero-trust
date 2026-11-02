# KẾT QUẢ KIỂM THỬ THỰC TẾ (SYSTEM TEST RESULTS)
**Dự án:** SecuDoc — Zero-Trust Document Integrity, Signed Checkpoint Ledger & Security Behavior Analytics  
**Nhánh làm việc:** `lta`  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  
**Thời gian thực thi:** Tháng 10/2026  
**Lệnh thực thi kiểm thử:** `python -m unittest discover tests -v`  
**Môi trường:** Windows, Python 3.11, SQLite 3, Cryptography 42+, scikit-learn 1.9+, NumPy 2.4+  

---

## 1. TỔNG HỢP KẾT QUẢ KIỂM THỬ (EXECUTIVE SUMMARY)

- **Tổng số Test Case:** **79 / 79**
- **Số lượng ĐẠT (PASS):** **79 (100.0%)**
- **Số lượng THẤT BẠI (FAIL):** **0 (0.0%)**
- **Số lượng LỖI (ERROR):** **0 (0.0%)**
- **Số lượng BỎ QUA (NOT RUN):** **0 (0.0%)**
- **Thời gian thực thi toàn bộ:** **~20.8 giây**

```text
Ran 79 tests in 20.893s
OK
```

---

## 2. BẢNG CHI TIẾT 79 TEST CASES THEO MODULE

### 2.1. Module Mật Mã Học Cốt Lõi (`tests/test_crypto.py` — 13 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-CRYPTO-01** | Tính toán băm SHA-256 test vector rỗng và chuỗi chuẩn | Khớp chuẩn NIST/FIPS 180-4 | Trùng khớp 100% | **PASS** |
| **TC-CRYPTO-02** | Hiệu ứng tuyết lở (Avalanche Effect) khi đảo 1 bit | > 40% bits thay đổi | 128/256 bits đổi (50.00%) | **PASS** |
| **TC-CRYPTO-03** | Khởi tạo, lưu trữ và nạp cặp khóa RSA 2048-bit | Keys 2048-bit hợp lệ | 2048-bit PEM verified | **PASS** |
| **TC-CRYPTO-04** | Ký số RSA-PKCS#1 v1.5 và xác minh hợp lệ | Signature 512 hex, verify=True | Verify trả về `True` | **PASS** |
| **TC-CRYPTO-05** | Từ chối chữ ký nếu digest bị đổi 1 ký tự | Verify trả về `False` | Verify trả về `False` | **PASS** |
| **TC-CRYPTO-06** | Từ chối chữ ký nếu xác minh bằng khóa công khai lạ | Verify trả về `False` | Verify trả về `False` | **PASS** |
| **TC-CRYPTO-07** | Tính toán và xác thực chuỗi khối Hash-Chain | `is_valid: True` | Chuỗi toàn vẹn, không gãy | **PASS** |
| **TC-CRYPTO-08** | Phát hiện can thiệp dữ liệu khối trong sổ cái băm | Báo vỡ tại Block 1 | `is_valid: False, broken_at: 1` | **PASS** |
| **TC-CRYPTO-09** | Tính toán 256 vector nhị phân cho Avalanche Heatmap | 256 phần tử 0/1 | Khớp chuẩn Hamming vector | **PASS** |
| **TC-CRYPTO-10** | Ký số Canonical Metadata Payload & chống sửa metadata | Sửa title/recipient/type -> False | Chữ ký vô hiệu hóa lập tức | **PASS** |
| **TC-CRYPTO-11** | KeyManager tự khôi phục public key và từ chối ghi đè | Tạo lại public key an toàn | Khôi phục public key chuẩn | **PASS** |
| **TC-CRYPTO-12** | Sinh mã QR chuẩn và giải mã thực nghiệm | Trích xuất đúng URL xác minh | QR decode khớp 100% | **PASS** |
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
| **TC-AUTH-01** | Đăng nhập tài khoản hợp lệ | Trả về thông tin user | Thành công | **PASS** |
| **TC-AUTH-02** | Đăng nhập sai mật khẩu | Trả về None | Xác thực thất bại an toàn | **PASS** |
| **TC-AUTH-03** | Brute-force lockout chống tấn công dò mật khẩu | Khóa sau 5 lần sai | Khóa 60s, HTTP 429 | **PASS** |
| **TC-AUTH-04** | Salt ngẫu nhiên và băm PBKDF2-HMAC-SHA256 | Hai salt khác nhau | Salt độc lập | **PASS** |
| **TC-AUTH-05** | Phân quyền truy cập theo vai trò (RBAC Middleware) | Chặn truy cập trái quyền | HTTP 403 Forbidden | **PASS** |

### 2.4. Module Quản Lý Tài Liệu & Vòng Đời (`tests/test_document.py` — 9 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-DOC-01** | Phát hành và ký số văn bản hợp lệ | Tạo doc record & audit block | Thành công | **PASS** |
| **TC-DOC-02** | Chống Path Traversal trong tên tệp đính kèm | Sanitize filename an toàn | Tên tệp được chuẩn hóa | **PASS** |
| **TC-DOC-03** | Thu hồi văn bản hợp lệ | Chuyển `REVOKED`, thêm block | Thu hồi thành công | **PASS** |
| **TC-DOC-04** | Chống thu hồi lặp (Double Revocation) | Báo lỗi tài liệu đã thu hồi | `ValueError` chặn thu hồi trùng | **PASS** |
| **TC-DOC-05** | Xử lý sự cố: Khóa tài khoản Issuer & thu hồi khẩn cấp | Khóa issuer, thu hồi tài liệu | Trả về `IncidentRevokeResult` | **PASS** |
| **TC-DOC-06** | Kiểm tra whitelist phần mở rộng tệp tại backend | Chặn .exe, .sh, .php, .bat | Báo lỗi phần mở rộng cấm | **PASS** |
| **TC-DOC-07** | Tra cứu tài liệu theo UUID | Trả về chi tiết văn bản | Tìm thấy đúng bản ghi | **PASS** |
| **TC-DOC-08** | Tra cứu tài liệu theo SHA-256 Hash | Trả về chi tiết văn bản | Tìm thấy đúng bản ghi | **PASS** |
| **TC-DOC-09** | Liệt kê danh sách tài liệu theo Issuer | Phân trang và lọc chuẩn | Lọc đúng theo ID | **PASS** |

### 2.5. Module An Ninh Web & Bảo Vệ Tấn Công (`tests/test_web_security.py` — 16 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-WEB-01..16** | CSRF Protection, Rate Limiting (CPU simulation), Open Redirect Prevention, File Upload Security, HTTP Security Headers | Chặn đứng mọi vector tấn công | Đạt 16/16 bài kiểm tra | **PASS** |

### 2.6. Module Kịch Bản Tấn Công Mở Rộng (`tests/test_attack_scenarios.py` — 11 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-ATTACK-01..11** | Bit-Flip Attack, Rogue Key Signature, Metadata Tamper, Genesis Tamper, Sandbox Isolation, Head-Hash Checkpoint | Môi trường sandbox cô lập, phòng thủ vững chắc | Đạt 11/11 bài kiểm tra | **PASS** |

### 2.7. Module Least Privilege & Cô Lập Dữ Liệu (`tests/test_rbac_least_privilege.py` — 5 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-RBAC-01** | Issuer A cố tình thu hồi tài liệu của Issuer B | Bị chặn `PermissionError` (403) | Chặn đứng trái quyền | **PASS** |
| **TC-RBAC-02** | Issuer A thu hồi tài liệu do chính mình phát hành | Thu hồi thành công | Chuyển `REVOKED` | **PASS** |
| **TC-RBAC-03** | Auditor kích hoạt xử lý sự cố nhưng truyền ID Auditor/Verifier | Bị từ chối (chỉ xử lý ISSUER) | `ValueError` chặn nhầm lẫn | **PASS** |
| **TC-RBAC-04** | Sổ cái rỗng với `require_genesis=True` | Báo không hợp lệ (`is_valid=False`) | `is_valid: False, broken_at: 0` | **PASS** |
| **TC-RBAC-05** | Truy cập chứng chỉ văn bản từ đơn vị khác / người lạ | Tên người nhận bị mask `T*** T*** B***` | Bảo vệ dữ liệu cá nhân (PII) | **PASS** |

### 2.8. Module Mốc Kiểm Toán Ký Số Độc Lập (`tests/test_checkpoint.py` — 5 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-CP-01** | Tạo Checkpoint ký số và đối soát sổ cái nguyên bản | Khớp 100%, `CHECKPOINT_VERIFIED` | Xác minh thành công | **PASS** |
| **TC-CP-02** | Kẻ gian sửa đổi metadata bên trong file Checkpoint JSON | Chữ ký số RSA bị vô hiệu | Báo lỗi chữ ký không hợp lệ | **PASS** |
| **TC-CP-03** | Dùng khóa công khai lạ để xác minh Checkpoint | Báo fingerprint mismatch | Từ chối khóa không tin cậy | **PASS** |
| **TC-CP-04** | Phát hiện Database Rollback (khôi phục bản backup cũ) | Phát hiện thiếu khối so với mốc | `HISTORY_ROLLBACK_DETECTED` | **PASS** |
| **TC-CP-05** | **Tấn công viết lại toàn bộ chuỗi (Full-Chain Rewrite):** Kẻ gian sửa Block 1 và tính lại toàn bộ hash phía sau. Hash Chain nội bộ bị đánh lừa (`is_valid=True`), nhưng Signed Checkpoint độc lập phát hiện đứt gãy ngay! | Bắt trọn gian lận lịch sử | `FULL_CHAIN_REWRITE_DETECTED` | **PASS** |

### 2.9. Module Phân Tích Hành Vi An Ninh & Machine Learning (`tests/test_behavior_analytics.py` — 6 Tests)
| Mã Test Case | Tên / Mục Tiêu Test Case | Kết Quả Mong Đợi | Kết Quả Thực Tế | Trạng Thái |
|:---|:---|:---|:---|:---:|
| **TC-ML-01** | Ghi nhận Security Event: Loại bỏ mật khẩu, token, private key | Nhật ký an ninh sạch sẽ, không lộ secret | Loại bỏ 100% token/password | **PASS** |
| **TC-ML-02** | Trích xuất đặc trưng hành vi (Feature Engineering) từ log | Vector số học 6 chiều chuẩn hóa | Vector 6 chiều chuẩn xác | **PASS** |
| **TC-ML-03** | Khả năng tái lập phân chia dữ liệu Train/Val/Test (Seed 42) | Bộ dữ liệu sinh nhất quán | Khớp 100% qua các lần chạy | **PASS** |
| **TC-ML-04** | Suy luận Isolation Forest: Đánh giá điểm Risk Score | Nhận diện đột biến phát hành ồ ạt | Risk Score >= 70, level HIGH/CRITICAL | **PASS** |
| **TC-ML-05** | Đánh giá qua Rule-Based Baseline cơ sở | Nhận diện vi phạm ngưỡng luật tĩnh | Cảnh báo RB-01, RB-02 kèm lý do | **PASS** |
| **TC-ML-06** | Cơ chế phòng ngừa khi thiếu mô hình ML (Fallback) | Tự động chuyển sang Rule-Based | Hoạt động liên tục, không crash | **PASS** |

---

## 3. BẢNG SO SÁNH THỰC NGHIỆM ĐỊNH LƯỢNG (MACHINE LEARNING BENCHMARK)

Thực hiện trên tập Test độc lập (N = 173 mẫu chưa từng xuất hiện trong quá trình huấn luyện và tinh chỉnh ngưỡng):

| Chỉ Số Đo Lường | Isolation Forest (ML Không Giám Sát) | Rule-Based Baseline (Luật Tĩnh Cơ Sở) | Nhận Xét Khoa Học |
|:---|:---:|:---:|:---|
| **Recall (Độ nhạy)** | **100.0%** (23/23 tấn công) | **100.0%** (23/23 tấn công) | Cả hai phương pháp bắt trọn các cuộc tấn công |
| **Precision (Độ chính xác)** | **67.7%** | **100.0%** | Isolation Forest nhạy hơn với các biến động biên |
| **False Positive Rate (Báo nhầm)** | **7.3%** (11/150 mẫu bình thường) | **0.0%** | Đánh đổi chấp nhận được để phòng ngừa Zero-day |
| **ROC-AUC** | **1.000** | N/A (Rời rạc) | Không gian phân cách bất thường hoàn hảo |
| **Độ trễ suy luận (Latency)** | **0.054 ms / mẫu** | **0.002 ms / mẫu** | Cực kỳ nhanh, hoàn toàn đáp ứng môi trường Production |

---

## 4. KẾT LUẬN NGHIỆM THU

1. **Tính kế thừa:** Toàn bộ 63 bài kiểm thử ban đầu vẫn vượt qua 100%. Không phá vỡ bất kỳ luồng hoạt động cũ nào.
2. **Tính nghiêm ngặt:** Bổ sung 16 bài kiểm thử mới chuyên sâu về Least Privilege, Signed Checkpoint và Machine Learning.
3. **Tính trung thực khoa học:** Mọi số liệu trong báo cáo và bảng điều khiển đều được đo đạc thực tế từ mã nguồn và tập test độc lập, không sử dụng số liệu giả lập trang trí.
