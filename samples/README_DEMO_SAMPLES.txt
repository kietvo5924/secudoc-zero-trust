HƯỚNG DẪN KÉO THẢ TỆP MẪU KHI THUYẾT TRÌNH (DEMO SAMPLES)
============================================================
1. Bang_Tot_Nghiep_Nguyen_Van_An.txt
   -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC)
   -> Chứng minh: Văn bản chính gốc 100%, chữ ký RSA khớp, mã băm SHA-256 khớp.

2. Bang_Tot_Nghiep_Nguyen_Van_An_TAMPERED.txt
   -> Nhập kèm UUID của Nguyễn Văn An (hoặc kéo thả)
   -> Kết quả: ĐỎ (TAMPERED_CONTENT)
   -> Chứng minh: Hệ thống phát hiện sửa điểm GPA từ 3.92 thành 4.00 nhờ sai lệch mã băm.

3. Bang_Diem_Tran_Thi_Bich.txt
   -> Kết quả: XANH LÁ (VERIFIED_AUTHENTIC)
   -> Chứng minh: Bảng điểm chuẩn của sinh viên Trần Thị Bích.

4. Chung_Chi_Le_Hoang_Phuc.txt
   -> Kết quả: VÀNG (REVOKED)
   -> Chứng minh: Văn bản từng có thật nhưng đã bị thu hồi kỷ luật; hệ thống chặn thành công.

5. Bang_Gia_Mao_Chua_Tung_Dang_Ky.txt
   -> Kết quả: VÀNG/ĐỎ (NOT_FOUND)
   -> Chứng minh: Văn bản trôi nổi bên ngoài, chưa từng được cơ quan cấp ký phát hành.
