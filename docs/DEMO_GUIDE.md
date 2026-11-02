# HƯỚNG DẪN TRÌNH DIỄN DEMO & GIẢI THÍCH XỬ LÝ DỮ LIỆU
**Dự án:** SecuDoc — Zero-Trust Document Verification, Signed Checkpoint Ledger & Security Behavior Analytics  
**Nhánh:** `lta` | **Môi trường chạy:** `python run_web.py` $\rightarrow$ `http://127.0.0.1:5000`

---

## BẢNG TÀI KHOẢN ĐĂNG NHẬP HỆ THỐNG

| Vai trò | Tên đăng nhập | Mật khẩu | Mục đích sử dụng |
| :--- | :--- | :--- | :--- |
| **Đơn vị phát hành (ISSUER)** | `issuer` | `IssuerSecurePass2026!` | Phát hành bằng cấp, ký số, thu hồi văn bản của trường |
| **Kiểm toán viên (AUDITOR)** | `auditor` | `AuditorPass2026!` | Tạo/duyệt Signed Checkpoint, xem ML Analytics, xử lý sự cố |
| **Người tra cứu công khai** | *(Không đăng nhập)* | *(Khách vãng lai)* | Kiểm tra tính xác thực bằng cấp, quét QR, bảo vệ PII |

---

# PHẦN 1: CÁC CHỨC NĂNG NGHIỆP VỤ CHÍNH

---

### CHỨC NĂNG 1: THẨM ĐỊNH VĂN BẢN — CHẾ ĐỘ 1: TIÊU CHUẨN (STANDARD VERIFICATION)

#### 1. Thao tác thế nào?
1. Mở trang chủ: `http://127.0.0.1:5000`.
2. Giữ nguyên tab mặc định: **"Chế Độ 1: Thẩm Định Tiêu Chuẩn (Tải Tệp Lên)"**.
3. Kéo thả file `samples/Bang_Tot_Nghiep_Nguyen_Van_An.txt` vào ô dropzone (hoặc bấm chọn tệp).
4. Bấm nút: **"Thẩm Định Toán Học Ngay Lập Tức"**.
5. **Kết quả quan sát:**
   - Trả về thẻ màu xanh lá: **`XÁC MINH THÀNH CÔNG: VĂN BẢN NGUYÊN BẢN VÀ CHÍNH GỐC 100%`**.
   - Hiển thị bảng chi tiết: Tên văn bằng, Người nhận (`N*** V*** A***` nếu chưa đăng nhập), Cơ quan phát hành, Mã băm SHA-256 và trạng thái chữ ký số hợp lệ.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** File nhị phân (PDF/DOCX/TXT/PNG) do người dùng tải lên.
- **Các bước xử lý tại hệ thống:**
  1. *Kiểm tra ranh giới:* Flask Gateway giới hạn dung lượng cứng $\le 10\text{MB}$ (`MAX_CONTENT_LENGTH`), nếu vượt quá sẽ ngắt kết nối với mã HTTP 413.
  2. *Băm nhị phân:* Hàm `calculate_bytes_hash(file_bytes)` đọc toàn bộ mảng byte và tính mã băm $\text{SHA-256}$ độ dài 64 ký tự hex.
  3. *Truy vấn trạng thái:* Hệ thống tìm kiếm bản ghi trong bảng `documents` theo `doc_hash`:
     - Nếu không thấy $\rightarrow$ Trả về `NOT_FOUND` (tài liệu giả mạo hoặc chưa từng đăng ký).
     - Nếu thấy $\rightarrow$ Tiếp tục truy vấn bảng `revocations` xem văn bản có bị kỷ luật thu hồi không.
  4. *Xác thực chữ ký số RSA-2048:* Tái cấu trúc chuỗi chuẩn tắc **Canonical Payload**:
     $$\text{CANONICAL\_V1} \parallel \text{doc\_uuid} \parallel \text{doc\_type} \parallel \text{title} \parallel \text{recipient\_name} \parallel \text{doc\_hash} \parallel \text{issuer\_name}$$
     Dùng **Root Public Key** của trường (`root_public.pem`) giải mã chữ ký lưu trong database để đối soát tính toàn vẹn.
  5. *Lọc PII:* Xóa trường `file_storage_path`, che mờ tên người nhận nếu người xem là khách vãng lai.
- **Dữ liệu đầu ra:** JSON kết quả thẩm định hiển thị trực quan lên giao diện web.

---

### CHỨC NĂNG 2: THẨM ĐỊNH VĂN BẢN — CHẾ ĐỘ 2: BẢO VỆ QUYỀN RIÊNG TƯ (CLIENT-SIDE WEB CRYPTO)

#### 1. Thao tác thế nào?
1. Tại trang chủ `http://127.0.0.1:5000`, bấm chuyển sang tab: **"Chế Độ 2: Thẩm Định Giảm Thiểu Dữ Liệu (Client-Side SHA-256)"**.
2. Kéo thả file `samples/Bang_Tot_Nghiep_Nguyen_Van_An.txt` vào ô dropzone màu xanh tím.
3. Bấm nút: **"Tra Cứu Mã Băm Từ Xa (0 Byte Upload)"**.
4. **Kết quả quan sát:**
   - Kết quả xác thực trả về ngay tức thì (độ trễ $\approx 0\text{ms}$).
   - Không có bất kỳ byte nội dung văn bản nào được tải qua mạng internet.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** File tài liệu nằm cục bộ trên máy tính của người dùng.
- **Các bước xử lý tại hệ thống:**
  1. *Đọc vào RAM trình duyệt:* JavaScript sử dụng `FileReader` đọc file vào mảng `ArrayBuffer` nằm trong bộ nhớ RAM của trình duyệt.
  2. *Băm bằng Web Crypto API:* Trình duyệt gọi trực tiếp hàm mã hóa của hệ điều hành:
     ```javascript
     const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
     ```
  3. *Giảm thiểu dữ liệu truyền tải:* Tệp tài liệu gốc **hoàn toàn ở lại máy người dùng**. Trình duyệt chỉ gửi chuỗi băm hex 64 ký tự lên API `/api/verify-hash`.
  4. *Xác thực máy chủ:* Backend nhận chuỗi hex 64 ký tự, tra cứu trong cơ sở dữ liệu và kiểm tra trạng thái thu hồi.
- **Dữ liệu đầu ra:** Kết quả xác thực trả về máy khách mà máy chủ không hề biết nội dung chi tiết bên trong văn bản (bảo đảm tính riêng tư tuyệt đối theo nguyên lý *Data Minimization*).

---

### CHỨC NĂNG 3: TRA CỨU & QUÉT MÃ QR CHỨNG THỰC SỐ (DIGITAL CERTIFICATE & QR VERIFICATION)

#### 1. Thao tác thế nào?
1. Sau khi thẩm định thành công ở Chức năng 1, bấm nút: **"Mở Phiếu Chứng Thực Số & Quét QR Code"** (hoặc truy cập `/certificate/<doc_uuid>`).
2. Màn hình mở ra trang Giấy chứng nhận điện tử trang trọng với:
   - Dấu mộc số của Trường Đại học.
   - Mã QR xác thực chuẩn quốc tế.
   - Vân tay khóa công khai gốc của Trường: `SHA256:XX:XX:...`.
3. Dùng camera điện thoại quét mã QR trên màn hình máy tính $\rightarrow$ Điện thoại tự động nhận diện liên kết và chuyển thẳng tới trang thẩm định chính gốc.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Mã `doc_uuid` của văn bản.
- **Các bước xử lý tại hệ thống:**
  1. *Lấy dữ liệu:* `doc_service.get_document_by_uuid(doc_uuid)`.
  2. *Kiểm tra phân quyền PII:* Nếu phiên làm việc không phải là chủ sở hữu hoặc Auditor $\rightarrow$ Tự động che mờ tên người nhận: `mask_recipient_name(name)` $\rightarrow$ `L*** H*** P***` và che bớt UUID.
  3. *Sinh mã QR:* Gọi thư viện `qrcode` mã hóa đường dẫn tuyệt đối: `http://<host>:5000/?uuid=<doc_uuid>` thành dữ liệu ảnh nhị phân PNG, sau đó chuyển thành chuỗi Base64 Data URI nhúng trực tiếp vào thẻ `<img src="data:image/png;base64,...">`.
  4. *Tính vân tay khóa gốc:* Trích xuất SubjectPublicKeyInfo DER từ khóa công khai RSA và tính SHA-256 để in mã vân tay niêm phong.
- **Dữ liệu đầu ra:** Trang chứng chỉ HTML độc lập, an toàn PII và có thể in ấn hoặc quét mã tra cứu di động.

---

### CHỨC NĂNG 4: PHÁT HÀNH VĂN BẢN MỚI & KÝ SỐ RÀNG BUỘC METADATA

#### 1. Thao tác thế nào?
1. Bấm nút **"Đăng Nhập"** ở góc trên phải $\rightarrow$ Đăng nhập tài khoản: `issuer` / `IssuerSecurePass2026!`.
2. Hệ thống chuyển hướng tới **Bảng Điều Khiển Phát Hành (Dashboard)**.
3. Điền thông tin vào form cấp phát:
   - Tiêu đề văn bản: *Bằng Tốt Nghiệp Đại Học Kỹ Sư Công Nghệ Thông Tin*
   - Họ và tên người nhận: *Lê Hoàng Phúc - MSSV 20269999*
   - Loại văn bản: chọn *DIPLOMA*
   - Chọn 1 file đính kèm từ máy tính (ví dụ file `.pdf` hoặc `.txt`).
4. Bấm nút: **"Ký Số RSA-2048 & Đóng Block Sổ Cái"**.
5. **Kết quả quan sát:**
   - Thông báo màu xanh lá: *Phát hành và ký số văn bản thành công!*.
   - Văn bản mới lập tức xuất hiện ở đầu bảng danh sách kèm mã UUID và thời gian cấp phát.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Thông tin form (tiêu đề, người nhận, loại văn bản) và mảng byte của file tải lên.
- **Các bước xử lý tại hệ thống:**
  1. *Kiểm tra whitelist file:* Hàm kiểm tra đuôi mở rộng, chỉ chấp nhận `.pdf`, `.docx`, `.png`, `.jpg`, `.txt`. Nếu là `.exe` hay `.sh` sẽ từ chối ngay lập tức.
  2. *Đánh giá rủi ro an ninh tài khoản (ML Behavior Analytics):* Hệ thống lấy các sự kiện của tài khoản `issuer` trong 15 phút gần nhất, trích xuất vector đặc trưng và đưa qua mô hình `IsolationForest`. Nếu điểm rủi ro `CRITICAL` (bị nghi ngờ chiếm quyền), hệ thống sẽ chặn thao tác phát hành và báo Kiểm toán viên.
  3. *Tính mã băm file:* $\text{doc\_hash} = \text{SHA256}(\text{file\_bytes})$.
  4. *Đóng gói Canonical Metadata Payload:*
     ```text
     CANONICAL_V1|{UUID}|DIPLOMA|Bằng Tốt Nghiệp...|Lê Hoàng Phúc|{doc_hash}|Phòng Đào Tạo & Khảo Thí Đại Học
     ```
  5. *Ký số mật mã:* Lấy khóa riêng `root_private.pem` ký lên chuỗi trên bằng thuật toán RSA-PKCS#1 v1.5 với SHA-256, sinh ra chữ ký số 512 ký tự hex.
  6. *Lưu trữ an toàn:* File tải lên được đổi tên thành `{UUID}.bin` lưu trong `data/uploads/`. Thông tin văn bản lưu vào bảng `documents`.
  7. *Nối khối kiểm toán (Hash Chain):* Lấy hash của block trước đó $H_{n-1}$, đóng block số $n$ với hành động `ISSUE` và lưu vào bảng `audit_blocks`.
- **Dữ liệu đầu ra:** Văn bản chính thức được cấp phát, lưu trữ bất biến và không thể sửa đổi.

---

### CHỨC NĂNG 5: THU HỒI VĂN BẢN & PHÂN QUYỀN TỐI THIỂU (LEAST PRIVILEGE REVOCATION)

#### 1. Thao tác thế nào?
1. Vẫn tại màn hình Dashboard của `issuer`, tìm một văn bản đang ở trạng thái **`Đang hiệu lực`**.
2. Tại cột Thao Tác, bấm nút màu đỏ: **"Thu Hồi"**.
3. Một hộp thoại popup hiện ra $\rightarrow$ Nhập lý do: *Sinh viên vi phạm quy chế kỷ luật tốt nghiệp*.
4. Bấm **"Xác Nhận Thu Hồi"**.
5. **Kết quả quan sát:**
   - Trạng thái văn bản đổi ngay sang: **`Đã thu hồi`**.
   - Thử đem file này ra trang chủ thẩm định $\rightarrow$ Hệ thống lập tức báo màu vàng: **`REVOKED: Văn bản đã bị thu hồi kỷ luật`** kèm lý do và thời gian thu hồi.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** `doc_uuid`, `reason` và `revoked_by` (ID tài khoản đang đăng nhập).
- **Các bước xử lý tại hệ thống:**
  1. *Kiểm tra quyền sở hữu (Least Privilege):*
     ```python
     if doc["issuer_id"] != current_user["id"]:
         raise PermissionError("Issuer không có quyền thu hồi tài liệu của đơn vị khác!")
     ```
  2. *Cập nhật trạng thái CSDL:* Đổi `documents.status = 'REVOKED'`.
  3. *Ghi nhận lý do:* Thêm 1 dòng vào bảng `revocations` lưu rõ thời gian, người thu hồi và lý do.
  4. *Đóng khối REVOKE vào Hash Chain:*
     $$\text{Payload} = \text{SHA256}(\text{"REVOCATION:"} \parallel \text{doc\_uuid} \parallel \text{reason})$$
     Tạo khối mới với action `REVOKE` nối tiếp vào sổ cái kiểm toán để không ai có thể âm thầm hủy thu hồi.
- **Dữ liệu đầu ra:** Văn bản bị vô hiệu hóa trên toàn hệ thống trong thời gian thực.

---

### CHỨC NĂNG 6: KIỂM TOÁN SỔ CÁI CHUỖI BĂM (HASH-CHAIN AUDIT LEDGER)

#### 1. Thao tác thế nào?
1. Đăng xuất tài khoản `issuer`, đăng nhập tài khoản: `auditor` / `AuditorPass2026!`.
2. Truy cập menu: **Sổ Cái Kiểm Toán** (`http://127.0.0.1:5000/audit`).
3. Bấm nút: **"Quét Toán Học Chuỗi Khối"**.
4. **Kết quả quan sát:**
   - Hệ thống hiển thị thông báo màu xanh lá: **`TOÀN BỘ SỔ CÁI TOÀN VẸN: Toàn bộ X khối trong sổ cái đều TOÀN VẸN và LIÊN TỤC về mặt mật mã học`**.
   - Bảng danh sách các khối hiển thị rõ ràng: Khối Genesis, các khối ISSUE, REVOKE kèm liên kết `Prev Hash` $\rightarrow$ `Block Hash`.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Toàn bộ danh sách các khối trong bảng `audit_blocks` sắp xếp theo `block_index`.
- **Các bước xử lý tại hệ thống:**
  Hàm `verify_audit_chain()` duyệt tuần tự từng khối từ 0 đến $N$:
  1. *Kiểm tra khối 0 (Genesis):* Phải có `prev_block_hash` toàn số 0 (`000000...`) và action là `GENESIS`.
  2. *Kiểm tra liên kết chuỗi:* Với mỗi khối $i \ge 1$, bắt buộc:
     $$\text{block}[i].\text{prev\_block\_hash} == \text{block}[i-1].\text{block\_hash}$$
  3. *Tính toán lại toàn bộ dữ liệu bên trong khối:*
     $$\text{Calculated\_Hash} = \text{SHA256}(\text{Index} \parallel \text{Prev\_Hash} \parallel \text{Timestamp} \parallel \text{Action} \parallel \text{UUID} \parallel \text{Payload\_Hash})$$
     Nếu `Calculated_Hash != Stored_Hash` $\rightarrow$ Báo ngay khối $i$ đã bị sửa trộm dữ liệu.
- **Dữ liệu đầu ra:** Kết quả phân tích tính toàn vẹn toán học của toàn bộ lịch sử hệ thống.

---

### CHỨC NĂNG 7: TẠO VÀ ĐỐI SOÁT MỐC KIỂM TOÁN KÝ SỐ (SIGNED CHECKPOINTS)

#### 1. Thao tác thế nào?
1. Vẫn tại trang **Sổ Cái Kiểm Toán** (`/audit`), nhìn vào panel: **"Mốc Kiểm Toán Ký Số Độc Lập (Signed Checkpoints)"**.
2. Bấm nút: **"Tạo Checkpoint Mới"**.
   - Màn hình xuất hiện thông tin Checkpoint mới: Số thứ tự `#1`, Khối xác nhận cuối, Thời gian ký và Mã vân tay khóa ký.
3. Bấm nút: **"Tải Checkpoint (.json)"** để tải bản checkpoint độc lập về máy tính.
4. Bấm nút: **"Đối Soát Với Checkpoint"**.
5. **Kết quả quan sát:**
   - Hệ thống báo: **`XÁC MINH CHECKPOINT HỢP LỆ: Sổ cái khớp chính xác 100% với mốc Checkpoint #1... Chữ ký số kiểm toán hợp lệ`**.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Toàn bộ các khối trong sổ cái tại thời điểm bấm tạo.
- **Các bước xử lý tại hệ thống:**
  1. *Kiểm tra trước khi tạo:* Sổ cái phải toàn vẹn thì mới cho phép tạo mốc tin cậy.
  2. *Trích xuất mốc:* Lấy khối cuối cùng (Last Block Index, Last Block Hash, Total Blocks).
  3. *Ký số Checkpoint:* Đóng gói Canonical Checkpoint:
     $$\text{CHECKPOINT\_CANONICAL\_V1} \parallel \text{version} \parallel \text{seq} \parallel \text{last\_idx} \parallel \text{total} \parallel \text{last\_hash} \parallel \text{prev\_cp} \parallel \text{fingerprint} \parallel \text{timestamp}$$
     Ký số chuỗi này bằng `Root Private Key` để niêm phong mốc thời gian và lưu vào bảng `checkpoints`.
  4. *Đối soát độc lập:* Khi bấm đối soát, hệ thống xác minh chữ ký của Checkpoint bằng Public Key, sau đó kiểm tra xem số lượng khối hiện tại có bị ít đi không (phát hiện Rollback) và hash của khối tại chỉ mục đó có trùng khớp không (phát hiện Full-Chain Rewrite).
- **Dữ liệu đầu ra:** Báo cáo kiểm toán độc lập đối chiếu giữa cơ sở dữ liệu và mốc tin cậy bên ngoài.

---

### CHỨC NĂNG 8: GIÁM SÁT HÀNH VI BẤT THƯỜNG BẰNG MACHINE LEARNING (SECURITY BEHAVIOR ANALYTICS)

#### 1. Thao tác thế nào?
1. Tại trang **Sổ Cái Kiểm Toán** (`/audit`), cuộn xuống panel: **"Phân Tích Hành Vi An Ninh & Thực Nghiệm Máy Học"**.
2. **Kết quả quan sát:**
   - 3 ô đồng hồ đo: Tổng sự kiện an ninh, Số cảnh báo bất thường, Trạng thái mô hình (`Isolation Forest + Baseline`).
   - Bảng so sánh khoa học hiển thị kết quả kiểm thử thực tế trên $N = 173$ mẫu độc lập:
     - **Recall:** $100\%$ (bắt trọn 23/23 cuộc tấn công).
     - **Precision:** $67.7\%$.
     - **False Positive Rate:** $7.3\%$.
     - **Độ trễ suy luận:** $0.054\text{ ms/mẫu}$.
   - Bảng **Nhật ký sự kiện an ninh gần đây** hiển thị chi tiết các thao tác đăng nhập, phát hành, thu hồi kèm địa chỉ IP và trạng thái.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Mọi thao tác người dùng (đăng nhập đúng/sai, phát hành, thu hồi, truy cập trái phép) kích hoạt hàm `log_event()`.
- **Các bước xử lý tại hệ thống:**
  1. *Lọc an toàn dữ liệu (Privacy Filter):* Hệ thống tự động loại bỏ triệt để các trường `password`, `token`, `secret`, `key` trước khi ghi vào bảng `security_events`.
  2. *Trích xuất đặc trưng (Feature Extraction):* Khi cần đánh giá một tài khoản, lấy các sự kiện trong cửa sổ trượt 15 phút và tính toán vector số học 6 chiều:
     ```python
     feature_vector = [
         login_failure_count,       # Số lần đăng nhập sai
         issue_burst_count,         # Số lượng văn bản phát hành ồ ạt
         revoke_burst_count,        # Số lượng văn bản thu hồi liên tiếp
         access_denied_count,       # Số lần cố truy cập trái quyền (401/403)
         off_hours_ratio,           # Tỷ lệ thao tác ngoài giờ hành chính (đêm)
         action_velocity_per_min    # Tốc độ thao tác (thao tác/phút)
     ]
     ```
  3. *Suy luận qua mô hình Isolation Forest:* Mô hình học máy không giám sát (`isolation_forest.pkl`) tính toán độ dị biệt của vector này so với phân phối bình thường, ánh xạ thành điểm rủi ro:
     $$\text{Risk Score} \in [0, 100]$$
  4. *Phân cấp cảnh báo:*
     - `0 - 39`: **LOW** (Bình thường).
     - `40 - 69`: **MEDIUM** (Bất thường nhẹ, ghi log theo dõi).
     - `70 - 84`: **HIGH** (Rủi ro cao, gửi cảnh báo cho Auditor).
     - `85 - 100`: **CRITICAL** (Nguy hiểm nghiêm trọng, tạm khóa quyền phát hành, gắn cờ `SUSPICIOUS`).
- **Dữ liệu đầu ra:** Cảnh báo giải thích rõ nguyên nhân cho Auditor (ví dụ: *Đăng nhập sai 5 lần lúc 2h sáng kết hợp phát hành 20 văn bản*).

---

### CHỨC NĂNG 9: XỬ LÝ SỰ CỐ KHI TÀI KHOẢN ISSUER BỊ XÂM PHẠM (INCIDENT RESPONSE)

#### 1. Thao tác thế nào?
1. Khi phát hiện tài khoản `issuer` bị rò rỉ mật khẩu hoặc có hành vi gian lận phát hành hàng loạt bằng giả, Auditor kích hoạt quy trình ứng cứu khẩn cấp.
2. Auditor thực hiện gửi yêu cầu xử lý sự cố qua API hoặc bảng điều khiển sự cố.
3. **Kết quả quan sát:**
   - Tài khoản `issuer` bị chuyển trạng thái thành **`COMPROMISED`** và bị khóa đăng nhập ngay lập tức.
   - Toàn bộ văn bản đang `ACTIVE` do tài khoản này phát hành bị thu hồi hàng loạt tự động.
   - Mỗi lệnh thu hồi được đóng khối niêm phong vào sổ cái kiểm toán.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** `issuer_id` của tài khoản bị xâm phạm và `reason` sự cố.
- **Các bước xử lý tại hệ thống:**
  1. *Kiểm tra vai trò mục tiêu:* Bắt buộc tài khoản mục tiêu phải có vai trò `ISSUER`. Nếu truyền nhầm ID của Auditor hoặc Verifier $\rightarrow$ Hệ thống từ chối thực hiện (chống phá hoại nhầm lẫn).
  2. *Khóa tài khoản:* `UPDATE users SET status = 'COMPROMISED' WHERE id = ?;`.
  3. *Thu hồi nguyên tử (Atomic Transaction):* Mở transaction CSDL, quét danh sách các văn bản của Issuer này, cập nhật trạng thái `REVOKED`, ghi lý do kỷ luật và nối từng khối thu hồi vào sổ cái `audit_blocks`.
- **Dữ liệu đầu ra:** Đối tượng `IncidentRevokeResult` trả về danh sách chi tiết các mã UUID đã thu hồi thành công để làm bằng chứng pháp lý sau sự cố.

---

# PHẦN 2: CÁC KỊCH BẢN TẤN CÔNG (ATTACK LAB DEMO)

Truy cập trang: `http://127.0.0.1:5000/attack-lab`.

---

### KỊCH BẢN TẤN CÔNG 1: SỬA ĐỔI DỮ LIỆU TỪNG BYTE (BIT-FLIP TAMPERING ATTACK)

#### 1. Thao tác thế nào?
1. Tại giao diện **Attack Lab**, tìm thẻ **Kịch Bản 1 (Bit-Flip Tampering Attack)**.
2. Bấm nút màu đỏ: **"Thực Thi Đảo 1 Bit & Thẩm Định Ngay"**.
3. **Kết quả quan sát:**
   - Xuất hiện cảnh báo màu đỏ: **`CẢNH BÁO: VĂN BẢN ĐÃ BỊ CAN THIỆP / SỬA ĐỔI NỘI DUNG!`**.
   - **Kính hiển vi soi byte (Byte Forensic Inspector):** Chỉ rõ byte tại vị trí đảo: ký tự gốc `'T'` (Hex: `0x54`, nhị phân: `01010100`) bị đổi đúng 1 bit thành ký tự `'U'` (Hex: `0x55`, nhị phân: `01010101`).
   - **Ma trận tuyết lở 256-bit (Avalanche Heatmap):** Bảng 256 ô vuông thể hiện 128/256 bit SHA-256 bị đảo màu ($\approx 50\%$).

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Nội dung nhị phân của văn bản mẫu trong bộ nhớ RAM.
- **Quá trình tấn công & phòng thủ:**
  1. Kẻ tấn công dùng phép toán bitwise XOR đảo đúng 1 bit nhị phân thứ 0 của 1 byte:
     $$\text{tampered\_byte} = \text{original\_byte} \oplus 0x01$$
  2. Tính toán mã băm SHA-256 của nội dung sau khi bị sửa.
  3. Do đặc tính **Hiệu ứng Tuyết lở (Avalanche Effect)** của SHA-256, chỉ cần đổi 1 bit đầu vào thì trung bình 50% số bit đầu ra (128 bit) bị biến đổi hoàn toàn.
  4. Mã băm mới không còn khớp với chữ ký số RSA-2048 đã được niêm phong bởi Nhà trường $\rightarrow$ Hệ thống phát hiện ngay và từ chối văn bản.

---

### KỊCH BẢN TẤN CÔNG 2: GIẢ MẠO CHỮ KÝ BẰNG CẶP KHÓA LẠ (ROGUE KEY SIGNATURE FORGERY)

#### 1. Thao tác thế nào?
1. Kéo xuống **Kịch Bản 2 (Rogue Key Signature Forgery)**.
2. Bấm nút màu vàng: **"Sinh Khóa Rogue & Thử Nghiệm Giả Mạo"**.
3. **Kết quả quan sát:**
   - Kẻ mạo danh tự sinh một cặp khóa RSA-2048 bất đối xứng mới toanh.
   - Tự ký số lên tài liệu và tự nhận mình là cơ quan phát hành hợp pháp.
   - Thẻ kết quả màu đỏ hiển thị: **`TẤN CÔNG GIẢ MẠO CHỮ KÝ BỊ CHẶN HOÀN TOÀN!`**.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Văn bản giả mạo do kẻ gian tự tạo.
- **Quá trình tấn công & phòng thủ:**
  1. Kẻ tấn công dùng thư viện `cryptography` sinh cặp khóa riêng `rogue_private_key` và tự ký lên mã băm của tệp.
  2. Khi gửi lên cổng thẩm định Zero-Trust, động cơ xác minh **không dùng khóa của kẻ tấn công** mà bắt buộc phải dùng **Root Public Key** (`root_public.pem`) được lưu trữ bảo vệ trong hệ thống máy chủ.
  3. Quá trình toán học giải mã chữ ký bằng Root Public Key thất bại: hàm `public_key.verify()` ném ngoại lệ `InvalidSignature`. Chữ ký bị phán quyết là giả mạo 100%.

---

### KỊCH BẢN TẤN CÔNG 3: VƯỢT RÀO THU HỒI VĂN BẢN (REVOCATION BYPASS ATTACK)

#### 1. Thao tác thế nào?
1. Đọc nội dung mô phỏng tại thẻ **Kịch Bản 3 (Revocation Bypass)**.
2. Để thử nghiệm thực tế:
   - Dùng tài khoản `issuer` thu hồi một văn bản (như hướng dẫn ở Chức năng 5).
   - Lấy chính file gốc nguyên bản đó đem ra trang chủ thẩm định lại.
3. **Kết quả quan sát:**
   - Dù file nguyên bản 100%, không bị sửa một bit nào, chữ ký số toán học vẫn hoàn toàn hợp lệ.
   - Hệ thống vẫn kiên quyết trả về thẻ cảnh báo màu vàng: **`REVOKED: Văn bản này đã bị cơ quan phát hành thu hồi kỷ luật!`**.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Tệp văn bằng gốc nguyên bản của người bị kỷ luật.
- **Quá trình tấn công & phòng thủ:**
  1. Kẻ gian lợi dụng việc chữ ký số RSA là bất biến để tuyên bố văn bằng vẫn có giá trị.
  2. Trong mô hình Zero-Trust của SecuDoc, kiểm tra chữ ký số chỉ là **Bước 1**.
  3. **Bước 2 bắt buộc:** Động cơ xác minh tra cứu bảng `revocations` theo thời gian thực (Real-time Revocation Check) và đối soát chéo với khối `REVOKE` trong Hash Chain.
  4. Nếu tìm thấy trạng thái thu hồi, hệ thống ngay lập tức ghi đè phán quyết thành `REVOKED` và hiển thị nguyên văn lý do kỷ luật.

---

### KỊCH BẢN TẤN CÔNG 4: TẢI MÃ ĐỘC & PATH TRAVERSAL (FILE UPLOAD SECURITY)

#### 1. Thao tác thế nào?
1. Đọc mô phỏng tại thẻ **Kịch Bản 4 (Mã Độc & Path Traversal)**.
2. Để thử nghiệm thực tế:
   - Đăng nhập `issuer`, tại form phát hành văn bản, cố tình chọn một file có tên chứa ký tự điều hướng thư mục: `../../Windows/System32/malware.exe` hoặc đổi đuôi tệp thành `.sh`, `.php`.
3. **Kết quả quan sát:**
   - Hệ thống từ chối ngay lập tức tại backend và hiển thị cảnh báo: *Phần mở rộng tệp không hợp lệ! Hệ thống chỉ chấp nhận: docx, pdf, png, txt...*.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Tệp tin độc hại có tên chứa ký tự duyệt thư mục (`../`).
- **Quá trình tấn công & phòng thủ:**
  1. *Chặn dung lượng (Bomb Protection):* Flask Gateway giới hạn cứng `MAX_CONTENT_LENGTH = 10 * 1024 * 1024` (10MB). Mọi nỗ lực tải tệp 1GB làm tràn RAM máy chủ đều bị ngắt kết nối HTTP 413.
  2. *Chặn mã độc thực thi (Extension Whitelisting):* Backend kiểm tra phần mở rộng theo danh sách trắng nghiêm ngặt tại `src/config.py`.
  3. *Làm sạch tên tệp (Sanitization):* Hàm `sanitize_filename()` loại bỏ toàn bộ dấu `/` và `\`, chỉ giữ lại tên cơ sở.
  4. *Lưu trữ cô lập (Storage Isolation):* Tệp được lưu dưới mã UUID sinh ngẫu nhiên `data/uploads/{UUID}.bin`, không lưu với tên gốc của người dùng, triệt tiêu hoàn toàn nguy cơ ghi đè tệp hệ thống.

---

### KỊCH BẢN TẤN CÔNG 5: SỬA DATABASE & VIẾT LẠI TOÀN BỘ SỔ CÁI (FULL-CHAIN REWRITE ATTACK)

#### 1. Thao tác thế nào?
1. Đăng nhập hệ thống, chuyển sang trang **Attack Lab** (`/attack-lab`).
2. Cuộn xuống mục **"Kịch Bản 5: Tấn Công Sửa Database & Viết Lại Toàn Bộ Chuỗi Sổ Cái (Full-Chain Rewrite Attack)"**.
3. Bấm nút màu đỏ: **"Thực Thi Tấn Công Viết Lại Chuỗi & Kiểm Chứng Phòng Thủ"**.
4. **Kết quả quan sát:**
   - Hệ thống mô phỏng kẻ tấn công sửa lén nội dung Block 1 và **tính toán lại toàn bộ mã băm các khối phía sau** trong database Sandbox.
   - Kết quả kiểm tra nội bộ: **`is_valid: True`** (chuỗi nội bộ bị đánh lừa).
   - Kết quả đối soát với Signed Checkpoint độc lập: Báo màu đỏ **`PHÁT HIỆN CAN THIỆP SỔ CÁI (FULL_CHAIN_REWRITE_DETECTED)`** do hash thực tế trong DB bị lệch khỏi mốc đã được ký số!
   - Bấm nút **"Khôi Phục Sandbox Về Trạng Thái Gốc"** để hoàn nguyên dữ liệu.

#### 2. Dữ liệu được xử lý thế nào?
- **Dữ liệu đầu vào:** Toàn bộ bảng `audit_blocks` trong SQLite.
- **Quá trình tấn công & phòng thủ:**
  1. *Tấn công:* Kẻ gian sửa trường `action` của Block 1 thành `TAMPERED_ACTION`. Sau đó chạy vòng lặp cập nhật:
     $$\text{block}[2].\text{prev\_block\_hash} = \text{new\_block}[1].\text{hash}$$
     $$\text{block}[3].\text{prev\_block\_hash} = \text{new\_block}[2].\text{hash} \dots$$
     Chuỗi hash-chain vẫn liên tục và vượt qua bài kiểm tra toán học nội bộ.
  2. *Phòng thủ bằng Signed Checkpoint:* Auditor đối chiếu mã băm của khối cuối cùng trong DB với trường `last_block_hash` nằm trong file `secudoc_checkpoint_seq1.json` được ký số bởi Root Key độc lập.
  3. Do hai mã băm khác nhau, hệ thống lập tức phát hiện lịch sử đã bị viết lại và chỉ đích danh khối bị làm giả.
