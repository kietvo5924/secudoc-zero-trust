BẢNG DANH MỤC TỆP MẪU 5 ĐỊNH DẠNG (PDF, DOCX, PNG, JPG, TXT) KHI DEMO
================================================================================
Hệ thống SecuDoc hỗ trợ đầy đủ 5 định dạng tệp. Khi kéo thả tệp vào web, hệ thống
sẽ băm SHA-256 các byte nhị phân và đối soát chữ ký số RSA-2048 / Sổ cái Blockchain.

1. ĐỊNH DẠNG PDF:
   - Bang_Tot_Nghiep_Nguyen_Van_An.pdf
     UUID: 9b2ddd8d-d8ab-4531-a658-3070e041a736
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Hợp lệ 100%)
   - Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.pdf
     UUID: 9b2ddd8d-d8ab-4531-a658-3070e041a736 (nhập UUID để đối soát)
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện sửa điểm GPA từ 3.92 lên 4.00)

2. ĐỊNH DẠNG DOCX (Word):
   - Bang_Diem_Tran_Thi_Bich.docx
     UUID: 207e1e91-5df4-4cda-95dc-da3332888074
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Bảng điểm chính quy hợp lệ)
   - Bang_Diem_Tran_Thi_Bich_TAMPERED.docx
     UUID: 207e1e91-5df4-4cda-95dc-da3332888074
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện sửa điểm môn học trong file Word)

3. ĐỊNH DẠNG PNG (Hình ảnh):
   - Giay_Khen_Sinh_Vien_Xuat_Sac.png
     UUID: df7ae8b5-2bdb-450f-ab72-f53cb3640c8f
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Giấy khen đồ họa hợp lệ)
   - Giay_Khen_Sinh_Vien_TAMPERED.png
     UUID: df7ae8b5-2bdb-450f-ab72-f53cb3640c8f
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Bị phát hiện chỉnh sửa đồ họa/đổi tên)
   - Chung_Nhan_Ky_Thuat_Vien_Phuc.png
     UUID: 5fdf89ca-1336-4463-b859-f8e7964e0300
     -> Kết quả: VÀNG CAM (REVOKED - Đã bị thu hồi do kỷ luật)

4. ĐỊNH DẠNG JPG (Hình ảnh / Thẻ sinh viên):
   - The_Sinh_Vien_Le_Hoang_Phuc.jpg
     UUID: 8c9ebf9e-0927-4edb-8282-2e88b982090c
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC - Thẻ sinh viên điện tử hợp lệ)
   - The_Sinh_Vien_TAMPERED.jpg
     UUID: 8c9ebf9e-0927-4edb-8282-2e88b982090c
     -> Kết quả: ĐỎ (TAMPERED_CONTENT - Thẻ sinh viên bị can thiệp dữ liệu)

5. ĐỊNH DẠNG TXT (Văn bản thuần):
   - Bang_Tot_Nghiep_Nguyen_Van_An.txt
     UUID: ea8dc26c-12d7-4566-82f1-3df0d61b1b6e
     -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC)
   - Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt
     UUID: ea8dc26c-12d7-4566-82f1-3df0d61b1b6e
     -> Kết quả: ĐỎ (TAMPERED_CONTENT)
   - Chung_Chi_Le_Hoang_Phuc.txt
     UUID: 81294202-bda3-4f67-aa2e-da843e681ccd
     -> Kết quả: VÀNG CAM (REVOKED)

6. TỆP TRÔI NỔI / CHƯA ĐĂNG KÝ:
   - Bang_Gia_Mao_Chua_Tung_Dang_Ky.pdf
   - Bang_Gia_Mao_Chua_Tung_Dang_Ky.txt
     -> Kết quả: KHÔNG TÌM THẤY TRONG HỆ THỐNG (NOT_FOUND / UNTRUSTED)
================================================================================
