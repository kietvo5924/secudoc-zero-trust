# BẢNG ĐỐI CHIẾU NGHIỆM THU ĐỒ ÁN (ACCEPTANCE CHECKLIST)
**Học phần:** Bảo Mật Mạng Máy Tính và Hệ Thống  
**Dự án:** SecuDoc - Tamper-Evident Digital Document Verification & Audit System  
**Ngày nghiệm thu:** Tháng 10/2026  
**Đánh giá tổng thể:** 100% ĐẠT (PASS TOÀN BỘ CÁC TIÊU CHÍ BẮT BUỘC)  

---

## BẢNG ĐỐI CHIẾU CHI TIẾT TỪNG TIÊU CHÍ

| STT | Yêu Cầu Đề Bài Học Phần | Vị Trí Mô Tả Trong Tài Liệu | Vị Trí Cài Đặt Trong Mã Nguồn | Test Case & Bằng Chứng | Trạng Thái | Ghi Chú Kỹ Thuật |
|:---:|:---|:---|:---|:---|:---:|:---|
| **1** | Xác định bài toán cụ thể, đối tượng sử dụng rõ ràng, phạm vi vừa sức | `docs/DECISION_AND_SCOPE.md`<br>`docs/REQUIREMENTS.md` (Mục 1, 2) | Toàn bộ package `src/` | `tests/test_document.py`<br>`tests/test_verification.py` | **PASS** | Bài toán thẩm định bằng cấp chống giả mạo; 3 personas rõ ràng (`Issuer`, `Verifier`, `Auditor`). |
| **2** | Xác định tài sản bảo vệ và các rủi ro an ninh chính | `docs/THREAT_MODEL.md` (Mục 1, 3)<br>`docs/FINAL_REPORT.docx` | `src/models/schemas.py`<br>`src/crypto/keys.py` | `tests/test_attack_scenarios.py` | **PASS** | Phân tích 5 nhóm tài sản (Khóa riêng RSA, tính toàn vẹn file, sổ cái băm, thông tin PBKDF2). |
| **3** | Thiết kế kiến trúc hệ thống và luồng dữ liệu (DFD) | `docs/ARCHITECTURE.md`<br>`docs/DATA_FLOW.md` | `src/web/app.py`<br>`src/services/` | `docs/diagrams/architecture_diagram.png`<br>`docs/diagrams/data_flow_diagram.png` | **PASS** | Kiến trúc 5 tầng an toàn; sơ đồ luồng dữ liệu DFD Cấp 0, Cấp 1 và sơ đồ tuần tự sequence diagram. |
| **4** | Đề xuất và triển khai cơ chế bảo mật phù hợp với rủi ro | `docs/SECURITY_CONTROLS.md`<br>`docs/FINAL_REPORT.docx` | `src/crypto/hashing.py`<br>`src/crypto/signature.py`<br>`src/crypto/merkle.py` | `tests/test_crypto.py`<br>`tests/test_attack_scenarios.py` | **PASS** | Triển khai SHA-256 chunked stream, RSA-2048 PKCS#1 v1.5, PBKDF2-HMAC (100k rounds) và Sổ cái Merkle. |
| **5** | Có ít nhất 1 tình huống đầu vào bị giả mạo, chỉnh sửa hoặc đánh cắp | `docs/THREAT_MODEL.md`<br>`docs/DEMO_GUIDE.md` (Mục 2) | `src/services/verify_engine.py`<br>`src/web/templates/attack_demo.html` | `tests/test_attack_scenarios.py::test_file_tampering_bit_flip`<br>`tests/test_attack_scenarios.py::test_forged_signature_attack` | **PASS** | Xây dựng 5 kịch bản tấn công: đảo 1 bit điểm GPA, làm giả chữ ký RSA, vượt rào thu hồi, sửa lén SQLite, Path Traversal. |
| **6** | Có prototype hoặc mô phỏng minh họa luồng hoạt động chính | `docs/DEMO_GUIDE.md`<br>`README.md` | `run_web.py`<br>`src/web/app.py`<br>`src/cli/secu_cli.py` | Ứng dụng web chạy trên `http://127.0.0.1:5000`<br>CLI chạy trên terminal | **PASS** | Prototype chạy end-to-end 100% offline trên Windows, giao diện dark mode hiện đại, hỗ trợ cả Web và CLI. |
| **7** | Có bộ test case chứng minh cả tình huống bình thường lẫn rủi ro | `docs/TEST_PLAN.md`<br>`docs/TEST_RESULTS.md` | Thư mục `tests/` (5 file test suites) | 25 / 25 test cases PASS<br>Lệnh: `python -m unittest discover` | **PASS** | Bao gồm unit test mật mã, integration test quy trình cấp/thu hồi, và automated exploit simulations. |
| **8** | Phân tích ít nhất một trade-off giữa an toàn, riêng tư, tiện lợi, chi phí | `docs/SECURITY_CONTROLS.md` (Mục 2)<br>`docs/FINAL_REPORT.docx` (Mục 8) | Triển khai kiến trúc Hash-based Verify | `docs/FINAL_REPORT.md` | **PASS** | Phân tích sâu 3 trade-offs: (1) Toàn vẹn vs Riêng tư; (2) Khắt khe nhị phân vs Tiện lợi; (3) Sổ cái cục bộ vs Blockchain. |
| **9** | Thể hiện nguyên tắc "Không phải mọi thông tin nhận được đều đáng tin cậy" | Xuyên suốt toàn bộ hệ thống | `src/services/verify_engine.py` | `tests/test_verification.py` | **PASS** | Mọi tệp tải lên đều là `UNTRUSTED` cho đến khi xác minh toán học qua đủ 5 bước độc lập. |
| **10** | Sản phẩm bàn giao: Báo cáo Word hoàn chỉnh (.docx) | `docs/FINAL_REPORT.docx` | `scripts/generate_report_docx.py` | File tồn tại, có mục lục, bảng biểu, ảnh sơ đồ | **PASS** | Báo cáo Word 15+ trang định dạng chuẩn mực học thuật, có trang bìa, bảng số liệu, tài liệu tham khảo. |
| **11** | Sản phẩm bàn giao: Báo cáo Markdown song song (.md) | `docs/FINAL_REPORT.md` | Thư mục `docs/` | Xem trực tiếp trên VSCode / GitHub | **PASS** | Bản Markdown đầy đủ nội dung kỹ thuật và đối chiếu. |
| **12** | Sản phẩm bàn giao: Slide thuyết trình (.pptx và .md) | `docs/FINAL_PRESENTATION.pptx`<br>`docs/SLIDES_OUTLINE.md` | `scripts/generate_slides_pptx.py` | File trình chiếu 12 slide thiết kế chuyên nghiệp | **PASS** | 12 slide thiết kế widescreen 16:9, màu sắc hiện đại, tích hợp sơ đồ kiến trúc và luồng dữ liệu. |
| **13** | Sản phẩm bàn giao: Sơ đồ kiến trúc và luồng dữ liệu có thể chỉnh sửa | `docs/diagrams/*.mermaid`<br>`docs/diagrams/*.png` | `scripts/export_diagrams.py` | Xuất thành công PNG 200 DPI | **PASS** | Có mã nguồn Mermaid có thể sửa và file ảnh PNG sắc nét. |
| **14** | Hướng dẫn vận hành và kịch bản demo từng bước | `docs/DEMO_GUIDE.md`<br>`README.md` | `run_web.py` | Sinh viên tự chạy và thuyết trình dễ dàng | **PASS** | Hướng dẫn chi tiết từng click chuột trên web và từng câu lệnh trên terminal. |
