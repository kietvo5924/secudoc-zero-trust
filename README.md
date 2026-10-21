# SecuDoc - Hệ Thống Xác Minh Chứng Thực Văn Bản Số Chống Giả Mạo
> **Học phần:** Bảo Mật Mạng Máy Tính và Hệ Thống  
> **Nguyên tắc cốt lõi:** *"Không phải mọi thông tin mà hệ thống nhận được đều đáng tin cậy. Tuyệt đối không mặc định tin đầu vào chỉ vì nó trông có vẻ thật."*  
> **Kiến trúc:** Zero-Trust Verification Pipeline kết hợp Chữ ký số RSA-2048, Mã băm SHA-256 và Sổ cái Bất biến Merkle Hash-Chain.

---

## 1. TỔNG QUAN DỰ ÁN

**SecuDoc** là giải pháp phần mềm an toàn thông tin toàn diện, giải quyết triệt để vấn nạn gian lận bằng cấp, sửa điểm bảng điểm và làm giả chứng chỉ học thuật/công văn điện tử.

Hệ thống cho phép:
1. **Cơ quan phát hành (Issuer - Đại học/Tổ chức):** Tải văn bản gốc lên, tính toán mã băm SHA-256, ký số bất đối xứng bằng Khóa Riêng RSA-2048 của trường, cấp mã định danh chứng thực (UUID) và ghi nhận vào Sổ cái mật mã liên hoàn.
2. **Người thẩm định độc lập (Verifier - Nhà tuyển dụng/Bên thứ ba):** Kéo thả tệp nhận được vào cổng kiểm tra công khai. Hệ thống thẩm định toán học độc lập trong <100ms; phát hiện ngay lập tức nếu tệp bị sửa đổi dù chỉ 1 ký tự (`TAMPERED_CONTENT`), hoặc chữ ký số bị làm giả (`INVALID_SIGNATURE`), hoặc văn bản đã bị cơ quan cấp thu hồi kỷ luật (`REVOKED`).
3. **Kiểm toán viên an ninh (Auditor):** Quét toán học toàn bộ chuỗi băm Merkle của sổ cái (Audit Ledger) để bảo đảm không ai (kể cả quản trị viên máy chủ) có thể can thiệp sửa lén cơ sở dữ liệu.
4. **Phòng thí nghiệm mô phỏng tấn công (Attack Lab):** Giao diện tương tác 1-chạm giúp giảng viên và sinh viên trực tiếp thực thi các kịch bản xâm nhập thực tế: tấn công đảo 1 bit nhị phân (Bit-flip attack), tấn công giả mạo khóa ký (Rogue RSA key forgery), tấn công sửa lén database, và tấn công Path Traversal.

---

## 2. YÊU CẦU MÔI TRƯỜNG & CÀI ĐẶT

Dự án được tối ưu hóa để chạy **100% offline trên hệ điều hành Windows cá nhân**, không tốn phí bản quyền và không phụ thuộc vào bất kỳ dịch vụ đám mây nào.

### 2.1. Yêu Cầu Hệ Thống Đã Được Xác Minh
- **Hệ điều hành:** Windows 10 / Windows 11
- **Python:** 3.10 trở lên (Đã kiểm chứng xuất sắc trên Python 3.14)
- **Các thư viện Python cần thiết:**
  - `cryptography>=42.0.0` (Mật mã học RSA-2048 & SHA-256)
  - `flask>=3.0.0` (Cổng dịch vụ Web & REST API Gateway)
  - `python-docx>=1.1.0` (Xuất báo cáo Word học thuật)
  - `python-pptx>=1.0.0` (Xuất slide trình chiếu PowerPoint)
  - `matplotlib>=3.8.0` & `pillow>=10.0.0` (Xuất sơ đồ kỹ thuật PNG)

### 2.2. Hướng Dẫn Cài Đặt Trong 1 Phút
Mở terminal PowerShell tại thư mục dự án:
```powershell
# 1. Cài đặt các thư viện phụ thuộc
pip install -r requirements.txt

# 2. Khởi tạo cơ sở dữ liệu, sinh khóa RSA và nạp dữ liệu mẫu
python scripts/init_db.py
```

---

## 3. HƯỚNG DẪN KHỞI CHẠY VÀ SỬ DỤNG

### 3.1. Khởi Chạy Ứng Dụng Web
```powershell
python run_web.py
```
Truy cập trình duyệt tại địa chỉ: **`http://127.0.0.1:5000`**

### 3.2. Tài Khoản Demo Sẵn Có
| Vai Trò | Tên Đăng Nhập | Mật Khẩu Mẫu | Quyền Hạn |
|:---|:---|:---|:---|
| **Người Phát Hành (Issuer)** | `issuer` | `IssuerSecurePass2026!` | Tải file, ký số RSA-2048, phát hành và thu hồi văn bản |
| **Kiểm Toán Viên (Auditor)** | `auditor` | `AuditorPass2026!` | Giám sát sổ cái mật mã, quét toàn vẹn chuỗi khối |
| **Người Thẩm Định (Verifier)** | *Không cần đăng nhập* | *Tự do truy cập* | Kéo thả tệp thẩm định Zero-Trust |

---

## 4. CHẠY BỘ KIỂM THỬ TỰ ĐỘNG (AUTOMATED TEST SUITE)

Toàn bộ logic nghiệp vụ, các hàm mật mã học và các kịch bản phòng thủ được kiểm chứng bằng 27 test cases tự động:
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```
**Kết quả thực tế:**
- **27 / 27 Test Cases PASS 100%** (Thời gian chạy: ~4.0 giây).
- Xem bảng kết quả chi tiết từng test case tại [docs/TEST_RESULTS.md](file:///C:/Users/Admin/Downloads/BaoMatMangMayTinhvaHeThong/DoAnCuoiKy/docs/TEST_RESULTS.md).

---

## 5. CÔNG CỤ DÒNG LỆNH (CLI UTILITY)

Bên cạnh giao diện web, hệ thống hỗ trợ công cụ dòng lệnh đầy đủ tính năng:
```powershell
# 1. Thẩm định tệp văn bản độc lập từ thư mục samples
python -m src.cli.secu_cli verify samples/Bang_Tot_Nghiep_Nguyen_Van_An.txt

# 2. Thẩm định phát hiện gian lận sửa điểm GPA
python -m src.cli.secu_cli verify samples/Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt --uuid 711a30a5-def0-4e81-9d36-0aedeb777867

# 3. Phát hành văn bản mới qua terminal
python -m src.cli.secu_cli issue path/to/file.pdf --title "Bang Tot Nghiep" --recipient "Nguyen Van A" --type "DIPLOMA"

# 4. Kiểm toán tính toàn vẹn chuỗi sổ cái
python -m src.cli.secu_cli audit
```

---

## 6. KỊCH BẢN THUYẾT TRÌNH VÀ CÁC YẾU TỐ "WOW" ĐỘT PHÁ

Xem tài liệu hướng dẫn thuyết trình chi tiết từng click chuột tại:  
👉 **[docs/DEMO_GUIDE.md](file:///C:/Users/Admin/Downloads/BaoMatMangMayTinhvaHeThong/DoAnCuoiKy/docs/DEMO_GUIDE.md)**

Các tính năng nổi bật tạo dấu ấn vượt trội trước hội đồng:
1. **Thẩm Định Riêng Tư Ngoại Tuyến (In-Browser Web Crypto Verifier):** 
   - Trình duyệt tự động băm SHA-256 trong RAM bằng JavaScript Web Crypto.
   - **0 byte dữ liệu cá nhân bị gửi lên mạng**, tuân thủ nghiêm ngặt **Nghị định 13/2023/NĐ-CP** và **GDPR**.
2. **Kính Hiển Vi Soi Byte & Ma Trận Tuyết Lở 256-Bit (Avalanche Heatmap):**
   - Trực quan hóa 256 bits của SHA-256 đổi màu đỏ rực rỡ khi chỉ đảo đúng 1 bit nhị phân ở byte đầu tiên (Hamming distance ~50%).
   - Kính hiển vi nhị phân chỉ rõ vị trí ký tự bị sửa đổi lén lút (Offset `0x0000`).
3. **Phiếu Chứng Thực Mật Mã Số Có Mã QR (Verifiable Digital Credential):**
   - Xuất giấy chứng nhận trang trọng có con dấu số và mã QR; cho phép quét bằng camera điện thoại để đối soát tức thì.
4. **Sổ Cái Khôi Phục Tự Lành (Self-Healing Audit Ledger):**
   - Trình diễn kẻ tấn công sửa lén SQLite -> Báo vỡ chuỗi -> Bấm 1 nút hoàn nguyên dữ liệu gốc sạch sẽ.
5. **Gói Tệp Mẫu Thuyết Trình Sẵn Có (`samples/`):**
   - Tích hợp sẵn đầy đủ 5 file mẫu (Văn bản gốc, Bảng điểm sửa điểm gian lận, Văn bản bị kỷ luật thu hồi, Văn bản chưa đăng ký).

---

## 7. CẤU TRÚC THƯ MỤC DỰ ÁN

```
secudoc/
├── run_web.py                       # Điểm khởi chạy Web Server
├── requirements.txt                 # Khai báo các thư viện phụ thuộc
├── .gitignore                       # Bảo vệ không commit secrets, database, tệp tạm
├── .env.example                     # Mẫu cấu hình môi trường an toàn
├── README.md                        # Tài liệu hướng dẫn sử dụng toàn diện
├── src/
│   ├── config.py                    # Cấu hình tham số mật mã & đường dẫn
│   ├── crypto/                      # Động cơ mật mã học cốt lõi
│   │   ├── hashing.py               # SHA-256 stream chunking & avalanche analysis
│   │   ├── keys.py                  # Quản lý cặp khóa RSA-2048 (PEM format)
│   │   ├── signature.py             # Ký số & xác minh RSA-PKCS#1 v1.5
│   │   └── merkle.py                # Thuật toán Sổ cái băm Merkle / Hash-Chain
│   ├── models/                      # Quản trị cơ sở dữ liệu SQLite
│   │   └── database.py              # Khởi tạo schema, đánh index & seed tài khoản
│   ├── services/                    # Tầng nghiệp vụ an toàn thông tin
│   │   ├── auth_service.py          # Băm PBKDF2 (100k rounds) & Decorator RBAC
│   │   ├── doc_service.py           # Quy trình phát hành, khử khuẩn & thu hồi
│   │   ├── audit_service.py         # Kiểm toán toàn vẹn sổ cái băm liên hoàn
│   │   └── verify_engine.py         # Động cơ thẩm định Zero-Trust 5 trạng thái
│   ├── web/                         # Giao diện Web Flask
│   │   ├── app.py                   # Application Factory & Security Headers
│   │   ├── static/css/style.css     # Giao diện Dark-mode Cybersecurity hiện đại
│   │   ├── static/js/app.js         # Xử lý kéo thả tệp & Ajax Attack Lab
│   │   └── templates/               # Giao diện HTML5 (Jinja2)
│   └── cli/
│       └── secu_cli.py              # Công cụ dòng lệnh Headless Terminal
├── tests/                           # Bộ 25 Test Cases tự động
│   ├── test_crypto.py               # Unit test SHA-256, RSA-2048, Merkle
│   ├── test_auth.py                 # Unit test PBKDF2 và RBAC
│   ├── test_document.py             # Test phát hành, thu hồi, Path Traversal
│   ├── test_verification.py         # Test 5 trạng thái chẩn đoán Zero-Trust
│   └── test_attack_scenarios.py     # Test tự động 5 kịch bản xâm nhập
├── docs/                            # Toàn bộ hồ sơ bàn giao đồ án
│   ├── DECISION_AND_SCOPE.md        # Khảo sát so sánh 6 đề tài & bảng điểm
│   ├── REQUIREMENTS.md              # Đặc tả yêu cầu hệ thống (MoSCoW)
│   ├── THREAT_MODEL.md              # Mô hình đe dọa STRIDE & Ma trận truy vết
│   ├── ARCHITECTURE.md              # Thiết kế kiến trúc 5 tầng & Sequence Diagrams
│   ├── DATA_FLOW.md                 # Sơ đồ luồng dữ liệu DFD Cấp 0 & Cấp 1
│   ├── SECURITY_CONTROLS.md         # Phân tích cơ chế mật mã & Trade-offs
│   ├── TEST_PLAN.md                 # Kế hoạch kiểm thử chi tiết
│   ├── TEST_RESULTS.md              # Bảng kết quả thực nghiệm 25/25 PASS
│   ├── DEMO_GUIDE.md                # Kịch bản demo từng bước cho buổi bảo vệ
│   ├── ACCEPTANCE_CHECKLIST.md      # Bảng nghiệm thu đối chiếu 14 tiêu chí
│   ├── FINAL_REPORT.docx            # BÁO CÁO WORD HỌC THUẬT HOÀN CHỈNH
│   ├── FINAL_REPORT.md              # Báo cáo Markdown song song
│   ├── FINAL_PRESENTATION.pptx      # SLIDE TRÌNH CHIẾU POWERPOINT 12 SLIDES
│   ├── SLIDES_OUTLINE.md            # Đề cương nội dung bài thuyết trình
│   └── diagrams/                    # Sơ đồ kỹ thuật PNG và mã nguồn Mermaid
└── scripts/                         # Các script hỗ trợ tự động hóa
    ├── init_db.py                   # Khởi tạo DB và seed dữ liệu mẫu
    ├── generate_report_docx.py      # Tự động xuất file Word FINAL_REPORT.docx
    ├── generate_slides_pptx.py      # Tự động xuất file PowerPoint FINAL_PRESENTATION.pptx
    └── export_diagrams.py           # Tự động xuất sơ đồ ảnh PNG độ phân giải cao
```

---

## 8. HẠN CHẾ & HƯỚNG PHÁT TRIỂN
- **Hạn chế:** Hệ thống bảo đảm tính toàn vẹn của tệp số học, không thay thế việc điều tra thực địa ngoài đời nếu kẻ gian tạo một hồ sơ giả mạo hoàn toàn từ đầu.
- **Hướng phát triển:**
  1. Tích hợp hạ tầng chứng thực số công cộng PKI X.509 quốc gia (Viettel-CA, VNPT-CA).
  2. Xây dựng ứng dụng di động quét mã QR chứa chữ ký nén để thẩm định offline hoàn toàn mà không cần mạng.
  3. Kết nối với thiết bị phần cứng bảo mật chuyên dụng (Hardware Security Module - HSM) để bảo vệ khóa riêng của tổ chức.
