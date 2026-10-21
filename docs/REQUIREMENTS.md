# TÀI LIỆU YÊU CẦU HỆ THỐNG (SYSTEM REQUIREMENTS SPECIFICATION)
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  

---

## 1. BỐI CẢNH VÀ MÔ TẢ VẤN ĐỀ
Trong kỷ nguyên số hóa giáo dục và doanh nghiệp, hàng triệu văn bản hành chính, bằng đại học, chứng chỉ chuyên môn, bảng điểm và hợp đồng số được phát hành dưới định dạng điện tử (PDF, DOCX, ảnh số). Tuy nhiên, các định dạng này rất dễ bị chỉnh sửa bằng các phần mềm thương mại (Adobe Acrobat, Photoshop, PDF editors) chỉ trong vài phút. 

Thực trạng gian lận bằng cấp và tài liệu học thuật gây ra tổn hại nghiêm trọng về uy tín cho các cơ sở giáo dục, làm sai lệch kết quả tuyển dụng của doanh nghiệp, và tiềm ẩn nguy cơ an ninh khi các chứng nhận năng lực bị làm giả.

**Nguyên tắc cốt lõi giải quyết vấn đề:**  
Một hệ thống bảo mật không bao giờ được tin cậy bất kỳ văn bản nào do người dùng hoặc bên thứ ba tải lên chỉ vì văn bản đó mang hình ảnh con dấu, chữ ký scanned, hay logo của trường đại học. Mọi tài liệu số phải được kiểm chứng thông qua các bằng chứng mật mã học toán học không thể chối bỏ (Mathematical Proof of Authenticity & Integrity).

---

## 2. CHÂN DUNG NGƯỜI DÙNG (USER PERSONAS)

### Persona 1: Người Phát hành (Issuer - Ví dụ: Phòng Đào tạo / Cơ quan Cấp bằng)
- **Vai trò:** Đại diện tổ chức có thẩm quyền ban hành tài liệu.
- **Mục tiêu:** Tải lên văn bản gốc, tạo chữ ký số mật mã xác nhận thẩm quyền, xuất mã xác thực QR/UUID cho sinh viên, và có quyền thu hồi tài liệu nếu phát hiện sai sót hoặc vi phạm kỷ luật.
- **Rủi ro đối mặt:** Khóa ký riêng (Private Key) bị lộ hoặc tài khoản bị chiếm đoạt.

### Persona 2: Người Thẩm định Độc lập (Verifier - Ví dụ: Nhà tuyển dụng, Trường đối tác, Công chúng)
- **Vai trò:** Bên thứ ba cần xác minh độ tin cậy của tài liệu do ứng viên/đương sự cung cấp.
- **Mục tiêu:** Tải tệp văn bản nhận được lên hệ thống để biết ngay lập tức: Văn bản có đúng là do trường cấp không? Nội dung có bị sửa đổi dù chỉ 1 ký tự không? Văn bản có bị thu hồi không?
- **Rủi ro đối mặt:** Bị kẻ gian cung cấp văn bản đã chỉnh sửa tinh vi mắt thường không thấy được.

### Persona 3: Kiểm toán viên An ninh (Security Auditor / Admin)
- **Vai trò:** Chịu trách nhiệm giám sát toàn vẹn hệ thống và chuỗi nhật ký phát hành.
- **Mục tiêu:** Kiểm tra chuỗi băm Merkle của sổ cái (Audit Ledger) xem có bị bất kỳ ai can thiệp vào cơ sở dữ liệu để hợp thức hóa một tài liệu giả hay không.

---

## 3. YÊU CẦU CHỨC NĂNG (FUNCTIONAL REQUIREMENTS - MoSCoW)

| Mã Yêu Cầu | Tên Chức Năng | Mô Tả Chi Tiết | Mức Độ Ưu Tiên |
|:---|:---|:---|:---:|
| **FR-01** | Xác thực Người dùng & Phân quyền | Hỗ trợ đăng nhập với mật khẩu băm PBKDF2; phân tách nghiêm ngặt 3 vai trò: `ISSUER`, `AUDITOR`, `PUBLIC_VERIFIER`. | **MUST** |
| **FR-02** | Khởi tạo & Quản lý Khóa Ký | Tự động sinh và bảo vệ an toàn cặp khóa RSA 2048-bit; xuất khóa công khai cho quy trình thẩm định. | **MUST** |
| **FR-03** | Tính Băm Văn bản Phân mảnh | Đọc tệp văn bản theo luồng khối (chunked stream), tính toán mã băm mật mã SHA-256 duy nhất đại diện cho nội dung. | **MUST** |
| **FR-04** | Ký số Văn bản & Xuất Chứng nhận | Sử dụng khóa riêng của Issuer để ký số lên mã băm và siêu dữ liệu văn bản theo chuẩn PKCS#1 v1.5 with SHA-256. | **MUST** |
| **FR-05** | Lưu trữ Sổ cái Bất biến (Hash Chain) | Mỗi tài liệu phát hành được gắn vào một block trong sổ cái băm liên hoàn; block mới chứa hash của block trước đó. | **MUST** |
| **FR-06** | Thẩm định Tính Toàn vẹn & Chữ ký | Người thẩm định tải tệp lên hoặc nhập Document ID; hệ thống tự tính lại SHA-256 và xác thực chữ ký số bằng Public Key. | **MUST** |
| **FR-07** | Phát hiện Can thiệp Dữ liệu (Tamper Detection) | Phát hiện sai lệch dù chỉ 1 byte giữa tệp thẩm định và tệp gốc; lập tức từ chối và cảnh báo trạng thái `TAMPERED_CONTENT`. | **MUST** |
| **FR-08** | Thu hồi Văn bản (Revocation) | Cho phép Issuer thu hồi văn bản kèm lý do; hệ thống tự động cập nhật trạng thái `REVOKED` và ghi nhật ký thu hồi vào sổ cái. | **MUST** |
| **FR-09** | Thẩm định Tính Toàn vẹn Sổ cái | Cho phép Auditor bấm nút kiểm tra toàn bộ chuỗi Hash Chain; phát hiện nếu bất kỳ bản ghi DB nào bị sửa đổi trực tiếp. | **MUST** |
| **FR-10** | Phòng Thí nghiệm Tấn công (Attack Lab) | Giao diện mô phỏng 4 kịch bản tấn công trực quan: Sửa 1 byte tệp, Giả mạo chữ ký, Sử dụng văn bản thu hồi, Tải tệp mã độc. | **MUST** |
| **FR-11** | Công cụ Dòng lệnh (CLI Utility) | Cung cấp script CLI cho phép ký số, thẩm định và chạy mô phỏng tấn công headless trên terminal. | **SHOULD** |
| **FR-12** | Xuất Báo cáo Thẩm định | Cho phép tải về phiếu kết quả thẩm định kèm chữ ký số và dấu thời gian dưới dạng JSON/PDF tóm tắt. | **COULD** |

---

## 4. YÊU CẦU PHI CHỨC NĂNG (NON-FUNCTIONAL REQUIREMENTS)

### 4.1. An toàn & Bảo mật (Security - NFR-SEC)
- **NFR-SEC-01 (Zero-Trust Input):** Mọi tệp tải lên, tham số đường dẫn, và trường dữ liệu form đều được kiểm tra tính hợp lệ (kiểm tra MIME type, dung lượng tối đa 10MB, khử ký tự điều hướng thư mục `../` chống Path Traversal).
- **NFR-SEC-02 (Secrets Protection):** Tuyệt đối không lưu khóa riêng hoặc mật khẩu dưới dạng văn bản rõ (cleartext). Mật khẩu được băm với PBKDF2-HMAC-SHA256 (100,000 rounds) kèm muối ngẫu nhiên (salt) 16 bytes.
- **NFR-SEC-03 (Session Security):** Cookie phiên làm việc được thiết lập cờ `HttpOnly`, `SameSite=Lax`, ngăn chặn tấn công XSS đánh cắp phiên.
- **NFR-SEC-04 (Safe Error Handling):** Thông báo lỗi gửi về cho người dùng không để lộ stack trace nội bộ, đường dẫn máy chủ hoặc khóa mật mã.

### 4.2. Hiệu năng & Khả năng Đáp ứng (Performance - NFR-PERF)
- **NFR-PERF-01:** Thời gian tính toán mã băm SHA-256 và xác minh chữ ký số RSA cho tệp 5MB dưới 100ms trên CPU cá nhân tiêu chuẩn.
- **NFR-PERF-02:** Cơ sở dữ liệu SQLite xử lý truy vấn xác minh văn bản dưới 10ms thông qua việc đánh chỉ mục (Index) trên trường `doc_hash` và `doc_uuid`.

### 4.3. Tính Khả dụng & Độc lập (Usability & Portability - NFR-PORT)
- **NFR-PORT-01:** Hoạt động 100% độc lập không cần kết nối mạng Internet.
- **NFR-PORT-02:** Chạy mượt mà trên hệ điều hành Windows 10/11 với Python 3.10+.

---

## 5. TIÊU CHÍ CHẤP NHẬN (ACCEPTANCE CRITERIA)

1. **Phát hành Văn bản:** Tải tệp PDF/DOCX lên -> Hệ thống trả về `doc_uuid`, mã băm SHA-256 (64 ký tự hex), chữ ký số RSA hợp lệ (512 ký tự hex) và ghi nhận thành công 1 block vào sổ cái băm.
2. **Thẩm định Thành công (Happy Path):** Tải lại đúng tệp gốc lên trang kiểm tra -> Kết quả trả về `VERIFIED_AUTHENTIC` kèm thông tin cơ quan cấp, thời gian cấp, và trạng thái hợp lệ màu xanh lá.
3. **Phát hiện Can thiệp (Tamper Detection):** Dùng trình soạn thảo thay đổi đúng 1 byte bất kỳ trong tệp rồi tải lên kiểm tra -> Hệ thống trả về `TAMPERED_CONTENT` màu đỏ, chỉ rõ mã băm tính toán không trùng khớp với mã băm đã ký ban đầu.
4. **Phát hiện Giả mạo Khóa (Forgery Detection):** Ký văn bản bằng một khóa RSA giả mạo khác -> Hệ thống từ chối xác minh chữ ký số với trạng thái `INVALID_SIGNATURE`.
5. **Phát hiện Văn bản Thu hồi (Revocation Detection):** Sau khi Issuer bấm thu hồi -> Bất kỳ ai kiểm tra tệp đó đều nhận được trạng thái `REVOKED` kèm lý do thu hồi và thời điểm thu hồi.
6. **Kiểm toán Chuỗi Bất biến (Audit Chain Verification):** Chạy hàm kiểm toán chuỗi băm -> Toàn bộ các block được liên kết chặt chẽ qua SHA-256. Nếu chỉnh sửa 1 trường dữ liệu trực tiếp trong SQLite -> Kiểm toán viên phát hiện chuỗi bị đứt gãy ngay tại block bị sửa.
