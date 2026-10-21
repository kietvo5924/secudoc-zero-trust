# MÔ HÌNH ĐE DỌA VÀ PHÂN TÍCH RỦI RO (THREAT MODEL - STRIDE)
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  

---

## 1. TÀI SẢN CẦN BẢO VỆ (PROTECTED ASSETS)

| Mã Tài Sản | Tên Tài Sản | Mô Tả & Giá Trị | Hậu Quả Nếu Bị Xâm Phạm |
|:---|:---|:---|:---|
| **AST-01** | Khóa Riêng Của Tổ Chức (Issuer Private Key) | Cặp khóa RSA-2048 dùng để ký chứng thực số. Là gốc tin cậy (Root of Trust) của toàn bộ hệ thống. | Kẻ tấn công có thể tự ký và phát hành vô số văn bản giả mạo hợp lệ, làm sụp đổ hoàn toàn uy tín của tổ chức. |
| **AST-02** | Tính Toàn Vẹn Văn Bản (Document Integrity) | Từng byte dữ liệu trong các tệp văn bản được ban hành (bảng điểm, chứng chỉ, công văn). | Dữ liệu bị thay đổi (ví dụ: điểm 4 thành điểm 9) dẫn đến sai lệch nghiêm trọng trong tuyển dụng và học thuật. |
| **AST-03** | Chữ Ký Số & Siêu Dữ Liệu (Digital Signatures & Metadata) | Chữ ký điện tử RSA-PKCS#1 v1.5 cùng các thông tin đính kèm (ngày cấp, người nhận, loại chứng chỉ). | Bị giả mạo hoặc gán ghép sai giữa văn bản của người này cho người khác. |
| **AST-04** | Sổ Cái Nhật Ký Bất Biến (Immutable Audit Ledger) | Chuỗi khối băm (Hash-chain) ghi vết toàn bộ các hành động phát hành và thu hồi chứng chỉ. | Kẻ tấn công nội bộ hoặc hacker có thể xóa dấu vết hành vi cấp bằng trái phép hoặc thu hồi bất hợp pháp. |
| **AST-05** | Thông Tin Xác Thực Quản Trị (User Credentials & Sessions) | Mật khẩu tài khoản `issuer` và `auditor`, cookie phiên làm việc. | Kẻ tấn công chiếm quyền quản trị để phát hành hoặc hủy bỏ văn bản tùy ý. |

---

## 2. RANH GIỚI TIN CẬY VÀ TÁC NHÂN (TRUST BOUNDARIES & ACTORS)

```
[ BÊN NGOÀI KHÔNG TIN CẬY ]
(Kẻ tấn công / Ứng viên gian lận / Người dùng Internet)
        │
        │ HTTP Requests / Form Data / Uploaded Files (PDF, DOCX)
        ▼
═══════════════════════════════════════════════════════════════════════════
[ RANH GIỚI TIN CẬY 1: Ranh Giới Vào (Input Boundary) ]
- Bộ kiểm tra đầu vào, giới hạn dung lượng, khử khuẩn tên tệp
- Bộ xác thực phiên làm việc & phân quyền vai trò (RBAC)
═══════════════════════════════════════════════════════════════════════════
        │
        ▼
[ VÙNG XỬ LÝ ỨNG DỤNG ĐƯỢC BẢO VỆ ]
- Verification Engine (Zero-Trust)
- Cryptographic Engine (RSA Signing / SHA-256 Hashing)
- Audit Service (Merkle / Hash-chain Ledger)
        │
═══════════════════════════════════════════════════════════════════════════
[ RANH GIỚI TIN CẬY 2: Ranh Giới Lưu Trữ (Storage Boundary) ]
- Khóa riêng được cách ly trong thư mục cấu hình có phân quyền OS
- Cơ sở dữ liệu SQLite được bảo vệ chống SQL Injection qua Parameterized Queries
- Sổ cái băm tự xác thực tính toàn vẹn độc lập với DB
═══════════════════════════════════════════════════════════════════════════
```

### Các Tác nhân Đe dọa (Threat Actors):
1. **Kẻ lừa đảo ngoài (External Fraudster):** Có tệp bằng cấp hợp lệ của người khác, sử dụng công cụ đồ họa sửa đổi tên/điểm số và nộp cho nhà tuyển dụng.
2. **Kẻ tấn công mạo danh (Impersonator / Key Forger):** Tự tạo cặp khóa RSA riêng, tự ký văn bản giả mạo và tuyên bố là do trường đại học ban hành.
3. **Kẻ tấn công mạng (Cyber Attacker / Script Kiddie):** Tấn công Web Server qua Path Traversal, tải lên mã độc webshell, hoặc gửi tệp dung lượng cực lớn để gây tràn RAM/CPU (DoS).
4. **Kẻ có đặc quyền nội bộ biến chất (Malicious Insider):** Có quyền truy cập vào cơ sở dữ liệu SQLite máy chủ, cố tình sửa đổi trực tiếp dữ liệu bản ghi để hợp thức hóa văn bản giả.

---

## 3. BẢNG MỐI ĐE DỌA THEO MÔ HÌNH STRIDE

| Mã Rủi Ro | Phân Loại STRIDE | Mô Tả Mối Đe Dọa | Tác Nhân | Khả Năng | Tác Động | Mức Rủi Ro | Biện Pháp Giảm Thiểu (Security Controls) | Mã Test Kiểm Chứng | Rủi Ro Còn Lại |
|:---|:---:|:---|:---:|:---:|:---:|:---:|:---|:---:|:---|
| **THR-01** | **Spoofing** | Kẻ tấn công tạo một cặp khóa RSA giả, ký văn bản và tuyên bố tài liệu là chính gốc từ tổ chức. | Kẻ giả mạo | Cao | Nghiêm trọng | **CAO** | Hệ thống chỉ sử dụng Public Key chính thức của tổ chức (Root Key) đã được cấu hình trước. Xác minh chữ ký số bằng Public Key chuẩn; nếu khóa lạ -> lập tức báo lỗi `INVALID_SIGNATURE`. | `TC-SEC-01` | Rất thấp (Toán học RSA 2048-bit không thể giải mã khóa riêng). |
| **THR-02** | **Tampering** | Kẻ gian dùng công cụ chỉnh sửa 1 ký tự điểm hoặc ngày cấp trong tệp PDF rồi đem đi thẩm định. | Ứng viên gian lận | Rất cao | Nghiêm trọng | **RẤT CAO** | Tính toán mã băm SHA-256 theo từng khối dữ liệu nhị phân của tệp. So sánh trực tiếp với mã băm đã được ký số ban đầu. Khác biệt dù chỉ 1 bit làm hash thay đổi hoàn toàn (Avalanche effect). | `TC-SEC-02` | Không có (Bảo đảm tuyệt đối theo tính chất một chiều của SHA-256). |
| **THR-03** | **Repudiation** | Cơ quan phát hành phủ nhận việc đã cấp một văn bản sau khi có tranh chấp pháp lý. | Tổ chức phát hành | Thấp | Trung bình | **TRUNG BÌNH** | Chữ ký số RSA-2048 PKCS#1 v1.5 kết hợp dấu thời gian và lưu vết vào Sổ cái băm bất biến (Immutable Hash Chain). Tổ chức không thể phủ nhận vì chỉ có khóa riêng của họ mới tạo được chữ ký tương ứng. | `TC-SEC-03` | Rất thấp. |
| **THR-04** | **Information Disclosure** | Khóa riêng RSA hoặc mật khẩu quản trị bị lộ do commit lên Git hoặc ghi vào log ứng dụng. | Hacker / Kẻ quét mã nguồn | Trung bình | Thảm họa | **CAO** | Tuyệt đối không commit file key hoặc secret lên Git (thêm vào `.gitignore`). Khóa riêng được sinh ngẫu nhiên khi khởi tạo, lưu trong file PEM có phân quyền chặt chẽ. Log hệ thống chỉ ghi lại hash và UUID, không bao giờ ghi secret. | `TC-SEC-04` | Rất thấp nếu tuân thủ quy tắc quản trị file. |
| **THR-05** | **Denial of Service** | Kẻ tấn công tải lên tệp zip/file dung lượng hàng gigabyte để làm cạn kiệt RAM/băng thông của máy chủ thẩm định. | Kẻ phá hoại | Trung bình | Trung bình | **TRUNG BÌNH** | Giới hạn `MAX_CONTENT_LENGTH = 10MB` ở tầng Flask/Web framework. Đọc và băm tệp theo cơ chế Stream/Chunk (64KB/lần), không nạp toàn bộ file vào RAM cùng lúc. | `TC-SEC-05` | Thấp. |
| **THR-06** | **Elevation of Privilege** | Người dùng thẩm định công khai cố tình truy cập vào URL cấp bằng hoặc thu hồi văn bản (`/issue`, `/revoke`). | Kẻ tò mò / Kẻ tấn công | Cao | Cao | **CAO** | Kiểm tra quyền nghiêm ngặt tại server-side (Decorator `@require_role('ISSUER')`). Cookie phiên HttpOnly được mã hóa và ký số bằng Flask Secret Key. Từ chối ngay lập tức mọi request không có phiên hợp lệ. | `TC-SEC-06` | Rất thấp. |
| **THR-07** | **Tampering (Internal)** | Quản trị viên cơ sở dữ liệu dùng phần mềm can thiệp sửa trực tiếp bảng SQLite để đổi trạng thái văn bản thu hồi thành hợp lệ. | Insider Threat | Thấp | Cao | **TRUNG BÌNH** | Sổ cái băm Merkle / Hash Chain: Mỗi block lưu `prev_block_hash`. Khi Auditor chạy kiểm tra, hàm băm liên hoàn được tái tính toán; nếu có 1 ô dữ liệu trong DB bị sửa, toàn bộ chuỗi từ điểm đó bị đứt gãy. | `TC-SEC-07` | Thấp (Sổ cái phát hiện 100% sự can thiệp nội bộ). |
| **THR-08** | **Tampering / Injection** | Tên tệp tải lên chứa ký tự độc hại `../../etc/passwd` hoặc `.exe` nhằm ghi đè tệp hệ thống (Path Traversal). | Hacker | Trung bình | Nghiêm trọng | **CAO** | Khử khuẩn tên tệp bằng hàm `secure_filename()`. Lưu trữ tệp bằng tên băm SHA-256 ngẫu nhiên `doc_uuid.bin`, hoàn toàn cô lập tên gốc của người dùng. | `TC-SEC-08` | Rất thấp. |

---

## 4. MA TRẬN TRUY VẾT BẢO MẬT (SECURITY TRACEABILITY MATRIX)

| Rủi Ro (Threat) | Biện Pháp Kiểm Soát (Control) | Module / Mã Nguồn Cài Đặt | Test Case Tương Ứng | Bằng Chứng Quan Sát Được |
|:---|:---|:---|:---|:---|
| **THR-01: Giả mạo khóa/chữ ký** | RSA-2048 PKCS#1 v1.5 Verification | `src/crypto/signature.py` (`verify_signature`) | `tests/test_attack_scenarios.py::test_forged_signature_attack` | Hệ thống trả về `status: "INVALID_SIGNATURE"`, HTTP 200/400, cờ cảnh báo đỏ. |
| **THR-02: Sửa 1 byte tệp** | SHA-256 Stream Hashing & Comparison | `src/crypto/hashing.py` (`calculate_file_hash`) | `tests/test_attack_scenarios.py::test_file_tampering_bit_flip` | Mã băm tính toán khác mã băm gốc; hệ thống trả về `status: "TAMPERED_CONTENT"`. |
| **THR-05: Tấn công tệp quá cỡ** | Flask Content-Length Enforcement | `src/web/app.py` (`MAX_CONTENT_LENGTH = 10MB`) | `tests/test_document.py::test_file_size_exceeded` | Trả về HTTP 413 (Payload Too Large), tiến trình không bị treo hay tràn RAM. |
| **THR-06: Vượt quyền hạn (IDOR)** | Server-side Role-Based Access Control | `src/services/auth_service.py` (`require_role`) | `tests/test_auth.py::test_unauthorized_issue_access` | Trả về HTTP 403 (Forbidden) hoặc chuyển hướng về Login; không thực thi tác vụ. |
| **THR-07: Sửa lén Database** | Tamper-evident Hash Chain Ledger | `src/crypto/merkle.py` (`verify_audit_chain`) | `tests/test_attack_scenarios.py::test_database_tampering_detection` | Hàm kiểm toán trả về `is_valid: False` kèm chỉ số `broken_at_block_index: N`. |
| **THR-08: Path Traversal** | Sanitization & UUID Storage Isolation | `src/services/doc_service.py` (`sanitize_filename`) | `tests/test_document.py::test_path_traversal_prevention` | Tên tệp độc hại bị bóc tách; file được lưu tại vị trí cô lập `data/uploads/<uuid>`. |
