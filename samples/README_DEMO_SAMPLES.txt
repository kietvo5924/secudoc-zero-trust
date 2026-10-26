BẢNG DANH MỤC TỆP MẪU 5 ĐỊNH DẠNG (PDF, DOCX, PNG, JPG, TXT) KHI DEMO
================================================================================
Hệ thống SecuDoc hỗ trợ đầy đủ 5 định dạng tệp. Khi kéo thả tệp vào web, hệ thống
sẽ băm SHA-256 các byte nhị phân và đối soát chữ ký số RSA-2048 / Sổ cái Blockchain.

1. ĐỊNH DẠNG PDF:
   - Bang_Tot_Nghiep_Nguyen_Van_An.pdf
     UUID: 98075a9f-0a1f-4281-9a68-c773c261c6b4
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Hợp lệ 100%)
   - Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.pdf
     UUID: 98075a9f-0a1f-4281-9a68-c773c261c6b4 (nhập UUID để đối soát)
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện sửa điểm GPA từ 3.92 lên 4.00)

2. ĐỊNH DẠNG DOCX (Word):
   - Bang_Diem_Tran_Thi_Bich.docx
     UUID: 8a4d0b95-d071-44df-b5c1-c397adf6b6a3
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Bảng điểm chính quy hợp lệ)
   - Bang_Diem_Tran_Thi_Bich_TAMPERED.docx
     UUID: 8a4d0b95-d071-44df-b5c1-c397adf6b6a3
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện sửa điểm môn học trong file Word)

3. ĐỊNH DẠNG PNG (Hình ảnh):
   - Giay_Khen_Sinh_Vien_Xuat_Sac.png
     UUID: 0861efc2-68a1-4afb-81b2-014dfefc7052
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Giấy khen đồ họa hợp lệ)
   - Giay_Khen_Sinh_Vien_TAMPERED.png
     UUID: 0861efc2-68a1-4afb-81b2-014dfefc7052
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện chỉnh sửa đồ họa/đổi tên)
   - Chung_Nhan_Ky_Thuat_Vien_Phuc.png
     UUID: b2730cc1-41e7-4a2e-bdc9-42d7cf0bb922
     -> Kết quả: VÀNG CAM (REVOKED - Đã bị thu hồi do kỷ luật)

4. ĐỊNH DẠNG JPG (Hình ảnh / Thẻ sinh viên):
   - The_Sinh_Vien_Le_Hoang_Phuc.jpg
     UUID: 5e293f24-4252-4664-907f-fc120304d0e1
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Thẻ sinh viên điện tử hợp lệ)
   - The_Sinh_Vien_TAMPERED.jpg
     UUID: 5e293f24-4252-4664-907f-fc120304d0e1
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Thẻ sinh viên bị can thiệp dữ liệu)

5. ĐỊNH DẠNG TXT (Văn bản thuần):
   - Bang_Tot_Nghiep_Nguyen_Van_An.txt
     UUID: 19b46b12-2fde-43d8-8180-e8bc8c2f2aa9
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC)
   - Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt
     UUID: 19b46b12-2fde-43d8-8180-e8bc8c2f2aa9
     -> Kết quả: ĐỎ (TAMPERED_CONTENT)
   - Chung_Chi_Le_Hoang_Phuc.txt
     UUID: 92131e08-9a45-42c7-8ef2-b04aff61f772
     -> Kết quả: VÀNG CAM (REVOKED)

6. TỆP TRÔI NỔI / CHƯA ĐĂNG KÝ:
   - Bang_Gia_Mao_Chua_Tung_Dang_Ky.pdf
   - Bang_Gia_Mao_Chua_Tung_Dang_Ky.txt
     -> Kết quả: KHÔNG TÌM THẤY TRONG HỆ THỐNG (NOT_FOUND / UNTRUSTED)
================================================================================
