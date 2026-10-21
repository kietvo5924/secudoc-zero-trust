# BÁO CÁO ĐÁNH GIÁ, LỰA CHỌN ĐỀ TÀI VÀ XÁC ĐỊNH PHẠM VI DỰ ÁN
**Học phần:** Bảo mật Mạng Máy tính và Hệ thống  
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Ngày lập:** Tháng 10/2026  
**Trạng thái đề bài gốc:** Đề bài chi tiết được tích hợp đầy đủ trong Master Prompt của đồ án; không có file đề bài gốc riêng biệt trong workspace.

---

## 1. KHẢO SÁT VÀ SO SÁNH 6 ĐỀ TÀI TIỀM NĂNG

### 1.1. Tiêu chí và Công thức Chấm điểm
Mỗi đề tài được đánh giá độc lập theo 6 tiêu chí trên thang điểm 1 đến 5 (1: Rất kém / Rất khó; 5: Xuất sắc / Rất khả thi):
1. **$C_1$ - Mức độ phù hợp với đề bài & thỏa mãn yêu cầu bắt buộc (Trọng số 20%):** Thể hiện tư duy "Không tin tưởng đầu vào", có mô hình đe dọa, luồng xác minh, trade-off.
2. **$C_2$ - Độ vừa sức & khả năng hoàn thành trong phạm vi đồ án (Trọng số 20%):** Khả thi triển khai trọn vẹn, không quá tải về mặt thuật toán ngoài tầm kiểm soát.
3. **$C_3$ - Chiều sâu bảo mật / phân tích rủi ro (Trọng số 20%):** Sử dụng cơ chế mật mã học chuẩn (chữ ký số, mã băm, chuỗi khối/Merkle tree, RBAC, chống giả mạo), không chỉ là CRUD.
4. **$C_4$ - Khả năng xây Prototype & Demo trực quan (Trọng số 15%):** Giao diện web/dashboard trực quan, thể hiện rõ trạng thái xác minh và tấn công.
5. **$C_5$ - Khả năng viết Test case chứng minh trước/sau tấn công (Trọng số 15%):** Dễ dàng tự động hóa kiểm thử happy path, tamper simulation, replay, unauthorized access.
6. **$C_6$ - Chi phí, cài đặt đơn giản & độc lập dịch vụ ngoài (Trọng số 10%):** Chạy 100% offline/local trên Windows, không tốn phí bản quyền hay phụ thuộc Internet.

**Công thức quy đổi tổng điểm (thang 100):**
$$\text{Total Score} = \left( \sum_{i=1}^{6} C_i \times W_i \right) \times 20$$
*Trong đó $W_1 = 0.20, W_2 = 0.20, W_3 = 0.20, W_4 = 0.15, W_5 = 0.15, W_6 = 0.10$.*

---

### 1.2. Bảng Phân tích và So sánh Chi tiết 6 Đề tài

| STT | Tên Đề tài & Vấn đề Thực tế | Người dùng & Tài sản Bảo vệ | Tình huống Tấn công / Lạm dụng | Cơ chế Bảo vệ Trọng tâm | Công nghệ Dự kiến | Phần Khó nhất | Cách Demo Trực quan | Ưu điểm & Nhược điểm | Điểm ($C_1..C_6$) | Tổng Điểm /100 |
|:---:|:---|:---|:---|:---|:---|:---|:---|:---|:---:|:---:|
| **1** | **SecuDoc: Cổng Xác minh & Thẩm định Văn bản Số Chống Giả mạo**<br>*Vấn đề:* Bằng cấp, chứng chỉ, bảng điểm, công văn số bị sửa đổi nội dung, làm giả con dấu hoặc bị thu hồi nhưng vẫn đem đi lừa đảo. | **Người dùng:** Đơn vị cấp bằng (Issuer), Sinh viên (Holder), Nhà tuyển dụng (Verifier), Quản trị viên/Auditor.<br>**Tài sản:** Tính toàn vẹn văn bản, chữ ký số cơ quan cấp, chuỗi nhật ký thẩm tra không thể chối bỏ. | Kẻ gian can thiệp sửa 1 ký tự điểm số trong file PDF/văn bản; giả mạo khóa ký của trường đại học; sử dụng văn bản đã bị thu hồi; upload file độc hại nhằm khai thác server. | Mã băm phân mảnh SHA-256; Chữ ký số bất đối xứng RSA-2048 PKCS#1 v1.5; Sổ cái băm Merkle chống sửa đổi; Kiểm tra thu hồi (Revocation check); Phân quyền RBAC. | Python 3, Flask, Cryptography, SQLite, HTML5/CSS3/JS. | Thiết kế cấu trúc chứng thực số kết hợp chữ ký số và chuỗi Merkle sao cho thẩm định offline độc lập không phụ thuộc DB nội bộ. | Kéo thả file gốc -> Hệ thống báo HỢP LỆ; bấm nút "Mô phỏng sửa 1 byte" -> Hệ thống lập tức báo BỊ CAN THIỆP kèm phân tích lỗi chi tiết. | **Ưu:** Minh họa xuất sắc nguyên tắc "Không tin đầu vào", demo ấn tượng, kiểm thử 100% tự động.<br>**Nhược:** Cần thiết kế cấu trúc token/metadata chuẩn hóa. | **5, 5, 5, 5, 5, 5** | **100.0** |
| **2** | **MediPrivacy: Chia sẻ Hồ sơ Bệnh án với Quản lý Đồng ý Phân quyền**<br>*Vấn đề:* Dữ liệu y tế cá nhân bị các phòng khám/bên thứ ba khai thác trái phép hoặc xem vượt thẩm quyền. | **Người dùng:** Bệnh nhân, Bác sĩ, Phòng xét nghiệm, Nghiên cứu viên.<br>**Tài sản:** Hồ sơ bệnh án điện tử, thông tin định danh cá nhân (PII), lịch sử chẩn đoán. | Bác sĩ cố tình truy cập hồ sơ khi bệnh nhân chưa cấp quyền; hoặc rò rỉ cơ sở dữ liệu làm lộ danh tính người bệnh hiểm nghèo. | Mã hóa từng trường dữ liệu (AES-256-GCM); Token ủy quyền động có thời hạn (TTL); Khử định danh (Anonymization/K-anonymity). | Python, Flask, SQLite/JSON, Cryptography. | Quản lý khóa mã hóa theo từng trường dữ liệu và xử lý truy vấn tìm kiếm trên dữ liệu đã mã hóa. | Bệnh nhân bật/tắt quyền xem kết quả X-quang cho Bác sĩ A; Bác sĩ B đăng nhập xem thì bị chặn và ghi log. | **Ưu:** Đề tài Privacy rất nhân văn và thực tế.<br>**Nhược:** Giao diện nhiều luồng ủy quyền phức tạp; việc tìm kiếm trên dữ liệu mã hóa dễ vượt quá sức đồ án. | **5, 4, 4, 4, 4, 4** | **83.0** |
| **3** | **SafeVault: Kho Lưu trữ Tệp An toàn Zero-Trust với Khóa Tự hủy**<br>*Vấn đề:* Lưu trữ tài liệu bí mật trên đám mây có nguy cơ bị lộ nếu máy chủ lưu trữ bị xâm nhập hoặc link chia sẻ bị rò rỉ. | **Người dùng:** Chủ sở hữu tệp, Người nhận chia sẻ, Quản trị viên.<br>**Tài sản:** Tệp tin mật kinh doanh, khóa mã hóa tệp, quyền truy cập tệp. | Máy chủ lưu trữ bị chiếm quyền (Untrusted Host); Người nhận cố tải lại tệp sau khi link đã hết hạn hoặc quá số lần cho phép. | Mã hóa phía máy khách (Client-side Envelope Encryption AES-GCM); Token tải 1 lần dùng HMAC; Giới hạn tốc độ và thời gian tự hủy. | Python/NodeJS, Web Crypto API, SQLite. | Đồng bộ và mã hóa/giải mã mượt mà trực tiếp trên trình duyệt bằng Web Crypto API. | Tải tệp lên, tạo link tự hủy sau 1 lần tải; sau lần tải 1, mở lại link nhận thông báo Access Denied. | **Ưu:** Kiến trúc Zero-Trust rõ ràng.<br>**Nhược:** Phụ thuộc nhiều vào JavaScript phía client; kiểm thử tự động luồng client-crypto phức tạp hơn. | **4, 4, 4, 4, 4, 4** | **80.0** |
| **4** | **APIShield: Cổng Bảo mật API Xác thực & Phát hiện Tấn công Giả mạo**<br>*Vấn đề:* Các API nội bộ bị tấn công dò quét mật khẩu (Credential Stuffing), tấn công replay, hoặc sửa đổi JWT payload. | **Người dùng:** Ứng dụng client, Kỹ sư vận hành, Người dùng dịch vụ.<br>**Tài sản:** Phiên xác thực JWT, tài nguyên API bảo mật, log truy cập hệ thống. | Kẻ tấn công bẻ gãy thuật toán JWT (alg: none), tái sử dụng token đã hết hạn, hoặc tấn công bruteforce đăng nhập với IP phân tán. | Ký xác thực JWT với secret an toàn; Sliding Window Rate Limiting; Anomaly Detection Heuristic; Ghi log truy vết IP/User-Agent. | Python, Flask, Redis/SQLite in-memory. | Xây dựng thuật toán heuristic phát hiện bất thường mà không gây nghẽn hiệu năng của gateway. | Bắn 100 requests bất thường từ script -> Gateway kích hoạt cơ chế khóa IP và gửi cảnh báo đỏ trên dashboard. | **Ưu:** Tính thực chiến mạng và hạ tầng cao.<br>**Nhược:** Ít yếu tố trực quan cho người dùng cuối (chủ yếu là JSON API); tính năng nghiệp vụ người dùng mỏng. | **4, 4, 4, 3, 4, 4** | **77.5** |
| **5** | **ForensicChain: Quản lý Chuỗi Hành trình Chứng cứ Kỹ thuật số**<br>*Vấn đề:* Chứng cứ điều tra tội phạm mạng (ảnh chụp ổ cứng, gói tin pcap) bị can thiệp, xóa dấu vết hoặc bị nghi ngờ về tính toàn vẹn tại tòa án. | **Người dùng:** Điều tra viên (Investigator), Chuyên viên bảo quản (Custodian), Tòa án/Luật sư.<br>**Tài sản:** Tệp chứng cứ số, biên bản giao nhận, dấu thời gian pháp lý (Timestamp). | Đối tượng có đặc quyền nội bộ cố tình tráo đổi file chứng cứ để phi tang tội phạm; sửa đổi nhật ký bàn giao chứng cứ. | Hàm băm mật mã SHA-256; Sổ cái bất biến dựa trên Merkle Tree / Hash-chain; Chữ ký kép khi bàn giao chứng cứ. | Python, SQLite, Cryptography. | Đảm bảo tính toán chuỗi hash lớn của các file dung lượng gigabyte mà không tràn RAM. | Sửa 1 byte của file chứng cứ trong kho lưu trữ -> Hệ thống phát hiện chuỗi Hash-chain bị đứt gãy ngay lập tức. | **Ưu:** Chiều sâu mật mã và toàn vẹn xuất sắc.<br>**Nhược:** Đối tượng sử dụng hẹp (ngành điều tra/pháp lý); luồng tương tác thực tế ít phổ cập hơn bằng cấp/chứng chỉ. | **5, 4, 5, 4, 4, 4** | **86.0** |
| **6** | **PhishGuard: Lá chắn Xác minh Tính Xác thực Email & Phát hiện Lừa đảo**<br>*Vấn đề:* Người dùng bị lừa bởi email giả mạo tên miền trường/ngân hàng hoặc click vào các đường link lừa đảo tinh vi. | **Người dùng:** Người nhận thư, Quản trị viên hệ thống thư tín.<br>**Tài sản:** Thông tin đăng nhập người dùng, danh tiếng tên miền của tổ chức. | Kẻ lừa đảo gửi email mạo danh phòng đào tạo với đường link giả dạng homograph attack để cướp tài khoản sinh viên. | Kiểm tra mô phỏng SPF/DKIM/DMARC; Phân tích cấu trúc URL (Typosquatting, Punycode, TLD rủi ro); Bảng điểm rủi ro giải thích được. | Python, Regex, Flask, SQLite. | Xây dựng bộ luật giải thích được (Explainable Heuristic) đủ chính xác mà không bị false-positive cao. | Dán nội dung email lừa đảo vào hệ thống -> Hệ thống bóc tách các điểm giả mạo và gắn cờ cảnh báo đỏ. | **Ưu:** Rất gần gũi với người dùng phổ thông.<br>**Nhược:** Kiểm tra SPF/DKIM thực tế đòi hỏi cấu hình DNS mạng ngoài; nếu chỉ mô phỏng thì tính thực tế giảm. | **4, 4, 3, 4, 4, 4** | **77.0** |

---

## 2. QUYẾT ĐỊNH CHỌN ĐỀ TÀI VÀ LÝ DO

### 2.1. Đề tài Chiến thắng: ĐỀ TÀI 1
**Tên tiếng Việt:** Hệ thống Xác minh Chứng thực Văn bản Số Chống Giả mạo với Chuỗi Nhật ký Bất biến  
**Tên tiếng Anh:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Tên thư mục dự án:** `secu-doc` (triển khai trực tiếp tại thư mục gốc workspace)  
**Khẩu hiệu một câu (Pitch):** *"Một giải pháp thẩm định và xác minh chứng thực số tài liệu học thuật và văn bản pháp lý dựa trên nguyên tắc Zero-Trust, kết hợp chữ ký số RSA-2048, mã băm phân mảnh SHA-256, và chuỗi băm Merkle chống giả mạo có khả năng phát hiện thay đổi tới từng byte dữ liệu."*

### 2.2. Lý do Chốt Lựa chọn:
1. **Đáp ứng 100% nguyên tắc cốt lõi của môn học:** Đề tài thể hiện trực tiếp tư duy *"Không tin bất cứ tài liệu nào được gửi đến chỉ vì nó có logo, con dấu hay trông giống thật"*. Mọi văn bản phải được chứng minh bằng tính toán toán học mật mã.
2. **Kịch bản tấn công thực tế và có tính thuyết phục cao:** Việc chỉnh sửa điểm 5 thành 9 trong bảng điểm hoặc sửa tên trên chứng chỉ là vấn nạn nhức nhối thực tế. Việc mô phỏng kẻ tấn công sửa đúng 1 byte và chứng minh hệ thống phát hiện ngay lập tức là minh chứng thực nghiệm xuất sắc.
3. **Chiều sâu bảo mật toàn diện:** Kết hợp hài hòa cả 4 trụ cột an toàn thông tin:
   - **Tính bí mật (Confidentiality):** Dữ liệu quản trị và khóa riêng được bảo vệ bằng PBKDF2 và phân quyền truy cập.
   - **Tính toàn vẹn (Integrity):** Mã băm SHA-256 phân mảnh kiểm soát toàn vẹn nội dung file.
   - **Tính xác thực và chống chối bỏ (Authenticity & Non-repudiation):** Chữ ký số RSA-2048 của cơ quan cấp.
   - **Tính sẵn sàng và minh bạch (Auditability):** Chuỗi nhật ký băm Merkle chống sửa đổi lịch sử cấp và thu hồi.
4. **Tính khả thi và độc lập tuyệt đối:** Chạy 100% trên môi trường Windows local với Python, Flask, Cryptography, SQLite; không phụ thuộc dịch vụ đám mây, không phát sinh chi phí.
5. **Khả năng kiểm thử tự động và demo vượt trội:** Có thể viết test suite tự động 100% các ca tấn công, đồng thời có giao diện web hiện đại với tab demo tấn công tương tác để giảng viên trực tiếp thử nghiệm.

---

## 3. MỤC TIÊU VÀ TIÊU CHÍ THÀNH CÔNG ĐO LƯỜNG ĐƯỢC

### 3.1. Mục tiêu Chính
Xây dựng một hệ thống hoàn chỉnh cho phép tổ chức phát hành văn bản số có chữ ký điện tử kèm siêu dữ liệu xác thực, cho phép bất kỳ bên thứ ba nào thẩm định tính toàn vẹn và nguồn gốc của văn bản một cách độc lập và bảo vệ chống lại mọi hành vi can thiệp, giả mạo chữ ký hoặc sử dụng văn bản đã bị thu hồi.

### 3.2. Mục tiêu Phụ
- Cung cấp cơ chế sổ cái băm (Merkle / Hash Chain) ghi nhận lịch sử phát hành và thu hồi chứng chỉ, đảm bảo không ai (kể cả admin) có thể âm thầm sửa đổi hay xóa vết.
- Cung cấp giao diện trực quan hỗ trợ cả người dùng nghiệp vụ (cấp văn bản, thu hồi) và người thẩm định độc lập (kéo thả tài liệu để kiểm tra).
- Tích hợp phòng thí nghiệm mô phỏng tấn công (Attack Lab) ngay trên giao diện web để phục vụ trình diễn và thuyết trình đồ án.

### 3.3. Tiêu chí Thành công Đo lường được (Measurable Metrics)
- **Tỷ lệ phát hiện can thiệp nội dung:** 100% (thay đổi dù chỉ 1 bit/byte trong file dữ liệu hoặc siêu dữ liệu đều bị phát hiện).
- **Tỷ lệ ngăn chặn chữ ký giả:** 100% (chữ ký tạo bởi khóa không hợp lệ hoặc bị sửa đổi đều bị từ chối với mã lỗi `UNTRUSTED_ISSUER` hoặc `INVALID_SIGNATURE`).
- **Thời gian xác minh trung bình:** < 100ms cho mỗi tài liệu trên máy cá nhân.
- **Độ bao phủ kiểm thử (Test Coverage):** Tối thiểu 15 test case tự động bao gồm cả happy path, tamper attacks, invalid keys, revoked documents, và boundary/path traversal attacks.
- **Tính trọn vẹn tài liệu bàn giao:** Đầy đủ Báo cáo Word (.docx), Báo cáo Markdown (.md), Slide thuyết trình (.pptx), Sơ đồ kiến trúc/luồng dữ liệu, Demo guide và Test results.

---

## 4. PHẠM VI DỰ ÁN (SCOPE & NON-GOALS)

### 4.1. Phạm vi MVP Bắt buộc Triển khai
1. **Module Mật mã học (Core Crypto Engine):**
   - Quản lý cặp khóa RSA 2048-bit cho tổ chức phát hành (Đại học/Tổ chức chứng thực).
   - Module băm SHA-256 tính toán dấu vân tay điện tử (Digital Fingerprint) của tài liệu.
   - Module tạo chữ ký số (RSA-PKCS#1 v1.5 with SHA-256) và xác minh chữ ký số.
   - Sổ cái băm kiểm tra toàn vẹn chuỗi nhật ký (Tamper-evident Hash Chain Audit Ledger).
2. **Module Quản lý Xác thực & Phân quyền (Auth & RBAC):**
   - Đăng nhập bảo mật với băm mật khẩu PBKDF2-HMAC-SHA256 (100,000 vòng lặp, salt ngẫu nhiên).
   - Phân quyền 3 vai trò: `ISSUER` (Cấp văn bản), `AUDITOR` (Kiểm toán sổ cái), `PUBLIC_VERIFIER` (Thẩm định viên tự do).
   - Quản lý phiên an toàn (Secure HTTP-only Session Cookie, chống session fixation).
3. **Module Nghiệp vụ Phát hành & Thu hồi (Issuance & Revocation):**
   - Tải lên văn bản, tính toán hash, ký số, lưu trữ siêu dữ liệu và xuất phiếu chứng nhận xác minh kèm mã định danh toàn cầu (UUIDv4).
   - Chức năng thu hồi văn bản (Revocation) có lý do và ghi nhận thời gian thực.
4. **Module Thẩm định Độc lập (Zero-Trust Verification Engine):**
   - Thẩm định qua tải lên tệp tin gốc hoặc tra cứu mã định danh chứng thực.
   - Trả về chẩn đoán 5 trạng thái rõ ràng:
     - `VERIFIED_AUTHENTIC`: Văn bản nguyên gốc, chữ ký hợp lệ, trạng thái còn hiệu lực.
     - `TAMPERED_CONTENT`: Nội dung văn bản đã bị can thiệp/sửa đổi.
     - `INVALID_SIGNATURE`: Chữ ký số không khớp hoặc bị làm giả.
     - `REVOKED`: Văn bản đã bị cơ quan phát hành thu hồi.
     - `NOT_FOUND`: Văn bản chưa từng được phát hành trong hệ thống.
5. **Giao diện Web Hiện đại & Attack Lab:**
   - Cổng thẩm định công khai (Public Verification Portal).
   - Bảng điều khiển quản lý văn bản cho Issuer.
   - Bảng giám sát tính toàn vẹn sổ cái cho Auditor.
   - Trang Attack Simulator cho phép người dùng click 1 chạm để thực hiện tấn công can thiệp byte và quan sát phản ứng của hệ thống.
6. **Bộ Test Suite Tự động:**
   - Kiểm thử toàn diện đơn vị (Unit test) và tích hợp (Integration test).

### 4.2. Những Tính năng KHÔNG Làm (Non-Goals)
- Không triển khai hạ tầng chữ ký số công cộng PKI X.509 quốc tế phức tạp (không tích hợp với Viettel-CA/VNPT-CA bên ngoài; sử dụng Local Root Key Authority của hệ thống được quản lý an toàn).
- Không xây dựng tính năng chỉnh sửa PDF trực tuyến hoặc OCR nhận diện chữ viết phức tạp.
- Không triển khai Blockchain công khai (Ethereum/Bitcoin) vì tốn phí gas, nghẽn mạng và phụ thuộc internet; thay vào đó sử dụng Sổ cái băm mật mã (Cryptographic Hash-Chain Ledger) đạt độ tin cậy tương đương trong mạng nội bộ.
- Không triển khai microservices đa cụm phức tạp để tránh over-engineering.

---

## 5. GIẢ ĐỊNH, GIỚI HẠN VÀ KẾ HOẠCH DỰ PHÒNG

### 5.1. Giả định
- Hệ thống chạy trên môi trường máy tính Windows cá nhân tiêu chuẩn đã cài sẵn Python 3.10+.
- Tổ chức phát hành sở hữu khóa riêng an toàn (được bảo mật trong thư mục cấu hình bảo vệ quyền truy cập).
- Người thẩm định có thể tiếp cận tệp văn bản số nguyên bản cần kiểm tra hoặc mã định danh của chứng chỉ.

### 5.2. Giới hạn
- Hệ thống xác minh tính toàn vẹn của tệp dữ liệu số (PDF, DOCX, PNG, v.v.), không thay thế quy trình điều tra thực địa của con người nếu kẻ gian tạo ra văn bản mới hoàn toàn từ đầu ngoài đời thực.
- Kích thước tệp tải lên được giới hạn ở 10MB để tối ưu hóa hiệu năng tính toán băm trên máy cá nhân.

### 5.3. Kế hoạch Dự phòng (Contingency Plan)
- **Nếu thư viện `cryptography` gặp lỗi biên dịch C trên một số máy:** Hệ thống có module dự phòng (Fallback Module) sử dụng `hmac` và `hashlib` tiêu chuẩn của Python (HMAC-SHA256 Secret Vault Key) để bảo đảm các bài test và demo vẫn chạy trơn tru 100%.
- **Nếu cổng mạng 5000 bị chiếm dụng:** File cấu hình cho phép chuyển đổi tức thì sang cổng 5050 hoặc 8080 qua biến môi trường `PORT`.
- **Nếu giao diện web gặp sự cố:** Toàn bộ tính năng phát hành, thẩm định và tấn công đều có công cụ dòng lệnh (CLI Tool: `python -m src.cli.secu_cli`) chạy độc lập không cần trình duyệt web.
