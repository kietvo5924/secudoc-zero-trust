# SecuDoc - Hệ Thống Xác Minh Chứng Thực Văn Bản Số Chống Giả Mạo
> **Học phần:** Bảo Mật Mạng Máy Tính và Hệ Thống  
> **Nguyên tắc cốt lõi:** *"Không phải mọi thông tin mà hệ thống nhận được đều đáng tin cậy. Tuyệt đối không mặc định tin đầu vào chỉ vì nó trông có vẻ thật."*  
> **Kiến trúc:** Zero-Trust Verification Pipeline kết hợp Chữ ký số RSA-2048 (ràng buộc Canonical Metadata), Mã băm SHA-256 và Sổ cái Kiểm toán Chuỗi Khối Mật mã (Cryptographic Hash-Chain Ledger).

---

## 1. TỔNG QUAN DỰ ÁN & RANH GIỚI BẢO VỆ

**SecuDoc** là đồ án môn học thuộc chuyên ngành An toàn thông tin, xây dựng prototype xác minh tính toàn vẹn và nguồn gốc của văn bản số, giải quyết vấn nạn gian lận bằng cấp, sửa điểm bảng điểm và giả mạo chứng chỉ học thuật.

Hệ thống cung cấp các năng lực kỹ thuật:
1. **Cơ quan phát hành (Issuer - Trường Đại học):** Tải văn bản gốc lên, tính toán mã băm SHA-256, ký số bất đối xứng RSA-2048 trên cấu trúc chuẩn hóa **Canonical Metadata Payload** (ràng buộc chặt chẽ mã hash tệp, mã UUID, họ tên người nhận, loại chứng chỉ và thời điểm cấp), cấp mã UUID và ghi nhận block mới vào Sổ cái kiểm toán.
2. **Người thẩm định (Verifier - Nhà tuyển dụng/Bên thứ ba):** Kéo thả tệp hoặc nhập mã UUID tại cổng thẩm định công khai. Hệ thống thẩm định toán học độc lập trong <100ms; phân loại rõ ràng các trạng thái:
   - `VERIFIED_AUTHENTIC`: Văn bản toàn vẹn 100%, chữ ký số và metadata khớp với sổ cái.
   - `TAMPERED_CONTENT`: Phát hiện tệp bị sửa đổi dù chỉ 1 bit nhị phân (Avalanche Effect > 40%).
   - `INVALID_SIGNATURE`: Phát hiện chữ ký giả mạo hoặc thông tin người nhận bị sửa lén trong CSDL.
   - `REVOKED`: Phát hiện văn bản đã bị cơ quan cấp thu hồi kỷ luật.
   - `REVOCATION_CONFLICT`: Phát hiện gian lận sửa trạng thái CSDL thành `ACTIVE` khi sổ cái đã ghi nhận lệnh thu hồi.
   - `AUDIT_CHAIN_BROKEN`: Phát hiện sổ cái kiểm toán bị xâm phạm hoặc vỡ liên kết chuỗi khối.
3. **Kiểm toán viên an ninh (Auditor):** Kiểm toán toàn vẹn chuỗi khối kiểm toán liên kết băm (`prev_block_hash`), phát hiện tức thì mọi hành vi sửa, xóa khối hoặc tráo đổi Genesis block.
4. **Phòng thí nghiệm mô phỏng tấn công (Attack Lab):** Giao diện tương tác 1-chạm giúp giảng viên và sinh viên diễn tập các kịch bản xâm nhập thực tế: đảo 1 bit nhị phân (Bit-flip), giả mạo khóa ký (Rogue RSA key), sửa lén CSDL trong Sandbox, và tấn công Path Traversal.

> [!NOTE]
> **Minh bạch về giới hạn học thuật:** SecuDoc là một prototype nghiên cứu phục vụ môn học, sử dụng cặp khóa gốc cục bộ (Local Root of Trust) của đơn vị cấp bằng; không tuyên bố là hệ thống cấp độ production, không thay thế cho PKI công cộng cấp quốc gia có thẩm quyền pháp lý và không thay thế phần mềm diệt virus.

---

## 2. YÊU CẦU MÔI TRƯỜNG & CÀI ĐẶT

Dự án được tối ưu hóa để chạy **100% offline trên máy tính cá nhân**, không tốn phí bản quyền và không phụ thuộc vào bất kỳ dịch vụ đám mây bên ngoài nào.

### 2.1. Môi Trường Đã Được Kiểm Chứng Thực Nghiệm
- **Hệ điều hành:** Windows 10 / Windows 11 / Linux (Ubuntu)
- **Python:** 3.10 đến 3.14 (Đã kiểm chứng xuất sắc trên Python 3.14.4)
- **Các thư viện phụ thuộc:**
  - `cryptography>=42.0.0` (Nguyên thủy mật mã RSA-2048 & SHA-256)
  - `flask>=3.0.0` (Cổng dịch vụ Web & API Gateway)
  - `qrcode>=7.4.2` & `pillow>=10.0.0` (Sinh mã QR chuẩn quét được bằng điện thoại)
  - `pyzbar>=0.1.9` (Giải mã và kiểm thử tự động tính hợp lệ của mã QR)
  - `python-docx>=1.1.0` & `python-pptx>=1.0.0` (Công cụ xuất báo cáo và slide tự động)

### 2.2. Hướng Dẫn Cài Đặt và Khởi Tạo Từ Clone Sạch
Mở terminal (PowerShell trên Windows hoặc Bash trên Linux) tại thư mục dự án:
```powershell
# 1. Cài đặt các thư viện phụ thuộc
pip install -r requirements.txt

# 2. Khởi tạo cơ sở dữ liệu và seed dữ liệu demo
python scripts/init_db.py --seed-demo
```

---

## 3. HƯỚNG DẪN KHỞI CHẠY VÀ SỬ DỤNG

### 3.1. Khởi Chạy Ứng Dụng Web
```powershell
python run_web.py
```
Truy cập trình duyệt tại địa chỉ: **`http://127.0.0.1:5000`**

### 3.2. Chế Độ Vận Hành & Tài Khoản Demo
Hệ thống hỗ trợ 2 chế độ cấu hình qua file `.env` (tham khảo `.env.example`):
- **`DEMO_MODE=1` (Mặc định cho đồ án):** Bật các tài khoản mẫu, hiển thị banner cảnh báo môi trường demo, mở cổng Attack Lab trên Sandbox Database riêng biệt (`data/attack_sandbox.db`).
- **`DEMO_MODE=0` (Chế độ Nghiêm Ngặt / Production):** Không seed tài khoản mẫu, bắt buộc phải khai báo `SECRET_KEY` mạnh trong `.env`, vô hiệu hóa các endpoint diễn tập can thiệp CSDL.

**Tài khoản mẫu trong chế độ Demo:**
| Vai Trò | Tên Đăng Nhập | Mật Khẩu Mẫu | Quyền Hạn & Phạm Vi |
|:---|:---|:---|:---|
| **Người Phát Hành (Issuer)** | `issuer` | `IssuerSecurePass2026!` | Cấp phát, ký số RSA-2048 và thu hồi văn bản |
| **Kiểm Toán Viên (Auditor)** | `auditor` | `AuditorPass2026!` | Giám sát sổ cái băm, quét toàn vẹn, diễn tập Attack Lab |
| **Người Thẩm Định (Verifier)** | *Không cần đăng nhập* | *Tự do truy cập* | Kéo thả tệp kiểm tra tính toàn vẹn và nguồn gốc |

---

## 4. CHẠY BỘ KIỂM THỬ TỰ ĐỘNG (AUTOMATED TEST SUITE)

Toàn bộ logic nghiệp vụ, các nguyên thủy mật mã học, các biện pháp an ninh web và các kịch bản phòng thủ được kiểm chứng bằng **46 test cases tự động**:
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```
**Kết quả thực nghiệm mới nhất:**
- **46 / 46 Test Cases PASS 100%** (Thời gian chạy: ~8.9 giây, 0 cảnh báo ResourceWarning).
- Xem báo cáo chi tiết từng test case tại [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md).
- Xem báo cáo kiểm toán an ninh ứng dụng tại [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).

---

## 5. CÔNG CỤ DÒNG LỆNH (CLI UTILITY)

Bên cạnh giao diện web, hệ thống hỗ trợ công cụ dòng lệnh:
```powershell
# 1. Thẩm định tệp văn bản độc lập từ thư mục samples
python -m src.cli.secu_cli verify samples/Bang_Tot_Nghiep_Nguyen_Van_An.txt

# 2. Thẩm định phát hiện gian lận sửa điểm GPA
python -m src.cli.secu_cli verify samples/Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt --uuid 711a30a5-def0-4e81-9d36-0aedeb777867

# 3. Phát hành văn bản mới qua terminal
python -m src.cli.secu_cli issue samples/sample_transcript.txt --title "Bang Diem" --recipient "Tran Van B" --type "TRANSCRIPT"

# 4. Kiểm toán tính toàn vẹn chuỗi sổ cái
python -m src.cli.secu_cli audit
```

---

## 6. KỊCH BẢN THUYẾT TRÌNH VÀ TÍNH NĂNG NỔI BẬT

Xem tài liệu hướng dẫn thuyết trình chi tiết từng click chuột tại:  
👉 **[docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md)**

Các tính năng tạo dấu ấn kỹ thuật vững chắc:
1. **Thẩm Định Giảm Thiểu Dữ Liệu Phía Client (Client-Side SHA-256 Data Minimization):**
   - Trình duyệt tự động băm SHA-256 trong RAM bằng JavaScript Web Crypto.
   - Nội dung tệp nhạy cảm không truyền qua mạng; chỉ mã băm và mã UUID được gửi lên máy chủ để tra cứu trạng thái thu hồi và đối soát chữ ký.
2. **Kính Hiển Vi Soi Byte & Ma Trận Tuyết Lở 256-Bit (Avalanche Heatmap):**
   - Trực quan hóa 256 bits của SHA-256 đổi màu khi chỉ đảo đúng 1 bit nhị phân ở byte đầu tiên (Hamming distance ~50%).
   - Kính hiển vi nhị phân chỉ rõ vị trí ký tự bị sửa đổi lén lút (Offset `0x0000`).
3. **Phiếu Chứng Thực Mật Mã Có Mã QR Quét Thật (Scannable QR Credential):**
   - Mã QR được tạo bằng thư viện chuẩn, mã hóa đúng URL xác minh; camera điện thoại có thể quét trực tiếp để mở trang chứng thực văn bản.
4. **Phòng Thí Nghiệm Tấn Công Cô Lập (Isolated Attack Sandbox):**
   - Diễn tập tấn công sửa lén CSDL trên file riêng biệt `data/attack_sandbox.db`, tuyệt đối bảo toàn cơ sở dữ liệu vận hành chính `data/secudoc.db`.
   - Cơ chế hoàn nguyên khối phục hồi dữ liệu thực từ snapshot của bất kỳ block index nào.
5. **Gói Tệp Mẫu Sẵn Có (`samples/`):**
   - Đi kèm 5 file mẫu phục vụ diễn tập (văn bản gốc, văn bản sửa điểm, văn bản bị thu hồi kỷ luật, văn bản chưa đăng ký).

---

## 7. CẤU TRÚC THƯ MỤC DỰ ÁN

```
secudoc/
├── .github/workflows/ci.yml         # CI Pipeline chạy tự động test trên Linux & Windows
├── run_web.py                       # Điểm khởi chạy Web Server
├── requirements.txt                 # Khai báo các thư viện phụ thuộc
├── .gitignore                       # Bảo vệ không commit secrets, database, tệp tạm
├── .env.example                     # Mẫu cấu hình môi trường an toàn
├── README.md                        # Tài liệu hướng dẫn sử dụng toàn diện
├── src/
│   ├── config.py                    # Nạp .env xác định, DEMO_MODE toggle, kiểm soát secret
│   ├── crypto/                      # Động cơ mật mã học cốt lõi
│   │   ├── hashing.py               # SHA-256 stream chunking & phân tích tuyết lở
│   │   ├── keys.py                  # Quản lý cặp khóa RSA-2048 & vân tay SHA256
│   │   ├── signature.py             # Ký số Canonical Metadata Payload & verify
│   │   ├── merkle.py                # Thuật toán Sổ cái kiểm toán Hash-Chain
│   │   └── qr.py                    # Sinh mã QR chuẩn PNG Data URI và SVG
│   ├── models/
│   │   └── database.py              # Context manager đóng connection an toàn, schema SQLite
│   ├── services/
│   │   ├── auth_service.py          # Băm PBKDF2 (100k rounds), RBAC, lockout chống brute-force
│   │   ├── doc_service.py           # Quy trình phát hành canonical, khử khuẩn & thu hồi
│   │   ├── audit_service.py         # Kiểm toán sổ cái, mô phỏng tấn công & phục hồi snapshot
│   │   └── verify_engine.py         # Động cơ thẩm định Zero-Trust 6 trạng thái chẩn đoán
│   ├── web/
│   │   ├── app.py                   # Application Factory, CSRF middleware, Open-Redirect filter
│   │   ├── static/css/style.css     # Giao diện Dark-mode Cybersecurity chuyên nghiệp
│   │   ├── static/js/app.js         # Client-side SHA-256, CSRF header injection, Attack Lab
│   │   └── templates/               # Giao diện HTML5 (Jinja2) với banner Demo & mã QR thật
│   └── cli/
│       └── secu_cli.py              # Công cụ dòng lệnh Headless Terminal
├── tests/                           # Bộ 45 Test Cases tự động (100% PASS)
│   ├── test_crypto.py               # Test SHA-256, Avalanche, RSA-2048, Canonical Payload, QR pyzbar
│   ├── test_auth.py                 # Test PBKDF2, Salts, Lockout rate-limiting, Demo suppression
│   ├── test_document.py             # Test phát hành, thu hồi, Path Traversal
│   ├── test_verification.py         # Test xác minh nội dung, metadata tamper, revocation conflict
│   ├── test_attack_scenarios.py     # Test 7 kịch bản tấn công, sandbox isolation, chain recalculation
│   └── test_web_security.py         # Test tích hợp Flask: CSRF, RBAC, PII Masking, Trust Info
├── docs/                            # Toàn bộ hồ sơ báo cáo đồ án
│   ├── SECURITY_AUDIT.md            # Báo cáo kiểm toán an toàn thông tin & khắc phục lỗ hổng
│   ├── TEST_RESULTS.md              # Bảng kết quả thực nghiệm 45/45 PASS
│   ├── DEMO_GUIDE.md                # Kịch bản demo từng bước cho buổi bảo vệ
│   ├── THREAT_MODEL.md              # Mô hình đe dọa STRIDE & ranh giới bảo mật
│   ├── ARCHITECTURE.md              # Thiết kế kiến trúc hệ thống
│   ├── SECURITY_CONTROLS.md         # Phân tích cơ chế kiểm soát an toàn & trade-offs
│   ├── FINAL_REPORT.docx            # BÁO CÁO WORD HỌC THUẬT HOÀN CHỈNH
│   └── FINAL_PRESENTATION.pptx      # SLIDE TRÌNH CHIẾU POWERPOINT HOÀN CHỈNH
└── scripts/                         # Các script hỗ trợ tự động hóa
    ├── init_db.py                   # Khởi tạo DB với cờ --seed-demo / --clean
    └── export_samples.py            # Tạo và đồng bộ 5 file mẫu trong samples/
```

---

## 8. GIỚI HẠN VÀ ĐỊNH HƯỚNG PHÁT TRIỂN
- **Giới hạn:** 
  1. Chứng thực dựa trên cặp khóa gốc cục bộ của cơ quan phát hành, chưa kết nối mạng lưới CA công cộng.
  2. Sổ cái Hash-Chain cục bộ bảo vệ chống can thiệp ngầm vào cơ sở dữ liệu; nếu kẻ tấn công có quyền Root hệ điều hành tính toán lại toàn bộ chuỗi băm thì cần cơ chế neo đỉnh chuỗi (Head Hash Checkpoint) ra bên ngoài để phát hiện.
  3. Thẩm định hoàn toàn ngoại tuyến không thể xác định được tính tươi mới của trạng thái thu hồi nếu không có kết nối kiểm tra cập nhật.
- **Hướng phát triển:**
  1. Tích hợp hạ tầng chứng thực số công cộng PKI X.509 quốc gia (VNPT-CA, Viettel-CA).
  2. Ứng dụng di động quét chứng chỉ số ngoại tuyến mang theo danh sách thu hồi định kỳ.
  3. Kết nối với module phần cứng bảo mật chuyên dụng (Hardware Security Module - HSM) để bảo vệ khóa riêng.
