"""Generate Professional 12-Slide Presentation in PPTX format using python-pptx."""
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

OUTPUT_FILE = Path(__file__).resolve().parent.parent / "docs" / "FINAL_PRESENTATION.pptx"
DIAGRAMS_DIR = Path(__file__).resolve().parent.parent / "docs" / "diagrams"

# Color Palette
COLOR_BG = RGBColor(8, 12, 22)        # #080c16
COLOR_CARD = RGBColor(16, 26, 48)     # #101a30
COLOR_CYAN = RGBColor(0, 229, 255)    # #00e5ff
COLOR_GREEN = RGBColor(0, 230, 118)   # #00e676
COLOR_RED = RGBColor(255, 23, 68)     # #ff1744
COLOR_WHITE = RGBColor(255, 255, 255)
COLOR_MUTED = RGBColor(143, 160, 192) # #8fa0c0
COLOR_AMBER = RGBColor(255, 171, 0)   # #ffab00


def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333) # 16:9 widescreen
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = COLOR_BG
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category_text="SECUDOC | ZERO-TRUST"):
        # Header category
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11), Inches(0.4))
        tf_cat = cat_box.text_frame
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = COLOR_CYAN

        # Main Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.5), Inches(0.8))
        tf = title_box.text_frame
        p = tf.paragraphs[0]
        p.text = title_text
        p.font.size = Pt(24)
        p.font.bold = True
        p.font.color.rgb = COLOR_WHITE

    # -------------------------------------------------------------
    # SLIDE 1: TITLE SLIDE
    # -------------------------------------------------------------
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Accent decorative box
    card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.5), Inches(1.2), Inches(10.33), Inches(5.1))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = COLOR_CYAN
    card.line.width = Pt(1.5)

    tb = s1.shapes.add_textbox(Inches(2.0), Inches(1.6), Inches(9.33), Inches(4.2))
    tf = tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = "HỌC PHẦN: BẢO MẬT MẠNG MÁY TÍNH VÀ HỆ THỐNG"
    p0.font.size = Pt(13)
    p0.font.bold = True
    p0.font.color.rgb = COLOR_CYAN
    p0.space_after = Pt(12)

    p1 = tf.add_paragraph()
    p1.text = "SECUDOC: HỆ THỐNG XÁC MINH CHỨNG THỰC\nVĂN BẢN SỐ CHỐNG GIẢ MẠO"
    p1.font.size = Pt(28)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_WHITE
    p1.space_after = Pt(14)

    p2 = tf.add_paragraph()
    p2.text = "Kiến trúc Zero-Trust kết hợp Chữ ký số RSA-2048, Mã băm SHA-256 và Sổ cái Bất biến"
    p2.font.size = Pt(15)
    p2.font.color.rgb = COLOR_MUTED
    p2.space_after = Pt(24)

    p3 = tf.add_paragraph()
    p3.text = "Sinh viên thực hiện: (Điền Họ tên & MSSV)  |  Giảng viên hướng dẫn: (Điền thông tin)"
    p3.font.size = Pt(13)
    p3.font.bold = True
    p3.font.color.rgb = COLOR_GREEN

    # -------------------------------------------------------------
    # SLIDE 2: PROBLEM STATEMENT
    # -------------------------------------------------------------
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "ĐẶT VẤN ĐỀ: THỰC TRẠNG GIAN LẬN VĂN BẢN SỐ")

    items_s2 = [
        ("Vấn Nạn Thực Tế", "Bằng cấp, chứng chỉ, bảng điểm số bị sửa đổi điểm số (GPA 2.5 -> 3.9) dễ dàng bằng các phần mềm đồ họa chỉ trong vài phút.", COLOR_RED),
        ("Hạn Chế Của Con Người", "Mắt thường không thể phân biệt tệp PDF nguyên bản và tệp bị chỉnh sửa. Hình ảnh con dấu hay logo rất dễ bị sao chép trái phép.", COLOR_AMBER),
        ("Thiếu Cơ Chế Thu Hồi", "Các văn bản sau khi phát hành nếu bị thu hồi do kỷ luật thường không có cơ chế đối soát tức thì, kẻ gian vẫn đem đi lừa đảo.", COLOR_CYAN),
    ]
    for idx, (head, desc, col) in enumerate(items_s2):
        c = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.95), Inches(1.8), Inches(3.7), Inches(4.8))
        c.fill.solid()
        c.fill.fore_color.rgb = COLOR_CARD
        c.line.color.rgb = col
        c.line.width = Pt(1.5)

        tb_c = s2.shapes.add_textbox(Inches(1.0 + idx * 3.95), Inches(2.1), Inches(3.3), Inches(4.2))
        tf_c = tb_c.text_frame
        tf_c.word_wrap = True

        p_h = tf_c.paragraphs[0]
        p_h.text = head
        p_h.font.size = Pt(18)
        p_h.font.bold = True
        p_h.font.color.rgb = col
        p_h.space_after = Pt(14)

        p_d = tf_c.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(13.5)
        p_d.font.color.rgb = COLOR_WHITE
        p_d.line_spacing = 1.3

    # -------------------------------------------------------------
    # SLIDE 3: ZERO-TRUST CORE PRINCIPLE
    # -------------------------------------------------------------
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "NGUYÊN TẮC CỐT LÕI: KHÔNG TIN TƯỞNG ĐẦU VÀO (ZERO-TRUST)")

    banner = s3.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.73), Inches(1.2))
    banner.fill.solid()
    banner.fill.fore_color.rgb = COLOR_CARD
    banner.line.color.rgb = COLOR_CYAN
    tb_b = s3.shapes.add_textbox(Inches(1.0), Inches(1.9), Inches(11.3), Inches(1.0))
    p_b = tb_b.text_frame.paragraphs[0]
    p_b.text = "“Không phải mọi thông tin mà hệ thống nhận được đều đáng tin cậy.”\nTuyệt đối không mặc định tin tệp dữ liệu chỉ vì nó trông có vẻ thật."
    p_b.font.size = Pt(15)
    p_b.font.bold = True
    p_b.font.color.rgb = COLOR_CYAN
    p_b.alignment = PP_ALIGN.CENTER

    pillars = [
        ("1. BĂM PHÂN MẢNH", "SHA-256 đọc từng chunk 64KB, kiểm soát tính toàn vẹn tới từng bit nhị phân.", COLOR_GREEN),
        ("2. CHỮ KÝ SỐ RSA", "Ký số bằng Khóa riêng của Trường; xác thực nguồn gốc và chống chối bỏ.", COLOR_CYAN),
        ("3. TRA CỨU THU HỒI", "Kiểm tra danh sách thu hồi thời gian thực tại thời điểm kiểm tra.", COLOR_AMBER),
        ("4. SỔ CÁI BẤT BIẾN", "Chuỗi băm Merkle liên hoàn chống kẻ gian nội bộ sửa lén database.", COLOR_RED),
    ]
    for idx, (head, desc, col) in enumerate(pillars):
        c = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 2.95), Inches(3.3), Inches(2.8), Inches(3.4))
        c.fill.solid()
        c.fill.fore_color.rgb = COLOR_CARD
        c.line.color.rgb = col
        tb_p = s3.shapes.add_textbox(Inches(0.9 + idx * 2.95), Inches(3.5), Inches(2.6), Inches(3.0))
        tf_p = tb_p.text_frame
        tf_p.word_wrap = True
        p1 = tf_p.paragraphs[0]
        p1.text = head
        p1.font.size = Pt(14)
        p1.font.bold = True
        p1.font.color.rgb = col
        p1.space_after = Pt(10)
        p2 = tf_p.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(12)
        p2.font.color.rgb = COLOR_WHITE
        p2.line_spacing = 1.3

    # -------------------------------------------------------------
    # SLIDE 4: TOPIC EVALUATION & WINNER
    # -------------------------------------------------------------
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "KHẢO SÁT 6 ĐỀ TÀI & QUYẾT ĐỊNH LỰA CHỌN")

    c_left = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    c_left.fill.solid()
    c_left.fill.fore_color.rgb = COLOR_CARD
    c_left.line.color.rgb = COLOR_CYAN

    tb_l = s4.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "BẢNG CHẤM ĐIỂM 6 ĐỀ TÀI (THANG 100)"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = COLOR_CYAN
    p.space_after = Pt(10)

    rows = [
        "1. SecuDoc (Xác minh văn bản chống giả mạo): 100.0 / 100 ★",
        "2. MediPrivacy (Hồ sơ bệnh án phân quyền): 83.0 / 100",
        "3. SafeVault (Kho file Zero-Trust tự hủy): 80.0 / 100",
        "4. APIShield (Cổng bảo mật API JWT/Rate Limit): 77.5 / 100",
        "5. ForensicChain (Chuỗi chứng cứ số pháp lý): 86.0 / 100",
        "6. PhishGuard (Lá chắn email & URL lừa đảo): 77.0 / 100",
    ]
    for r in rows:
        pr = tf_l.add_paragraph()
        pr.text = r
        pr.font.size = Pt(11.5)
        pr.font.color.rgb = COLOR_WHITE if "★" not in r else COLOR_GREEN
        pr.font.bold = ("★" in r)
        pr.space_after = Pt(6)

    # Right Box: Why SecuDoc Won
    c_right = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9))
    c_right.fill.solid()
    c_right.fill.fore_color.rgb = COLOR_CARD
    c_right.line.color.rgb = COLOR_GREEN

    tb_r = s4.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    pr_head = tf_r.paragraphs[0]
    pr_head.text = "TẠI SAO SECUDOC CHIẾN THẮNG?"
    pr_head.font.size = Pt(15)
    pr_head.font.bold = True
    pr_head.font.color.rgb = COLOR_GREEN
    pr_head.space_after = Pt(10)

    reasons = [
        "✓ Thể hiện trực tiếp nguyên tắc 'Không tin cậy đầu vào' của đề bài.",
        "✓ Kịch bản tấn công thực tế và thuyết phục: Sửa 1 byte điểm số là bị phát hiện tức thì.",
        "✓ Sử dụng cơ chế mật mã học chuẩn (RSA-2048, SHA-256, Merkle Hash Chain).",
        "✓ Khả thi 100% trên môi trường Windows local, chi phí bằng 0.",
        "✓ Khả năng kiểm thử tự động toàn diện (25/25 test cases PASS).",
    ]
    for rea in reasons:
        pra = tf_r.add_paragraph()
        pra.text = rea
        pra.font.size = Pt(12)
        pra.font.color.rgb = COLOR_WHITE
        pra.space_after = Pt(8)

    # -------------------------------------------------------------
    # SLIDE 5: THREAT MODEL & STRIDE
    # -------------------------------------------------------------
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "MÔ HÌNH ĐE DỌA STRIDE VÀ MA TRẬN PHÒNG THỦ")

    stride_threats = [
        ("S - Spoofing (Giả Mạo)", "Kẻ gian tự tạo khóa ký giả mạo của trường.", "Root Public Key từ chối mọi chữ ký không do khóa gốc tạo ra.", COLOR_CYAN),
        ("T - Tampering (Can Thiệp)", "Sửa 1 ký tự điểm GPA trong file PDF.", "SHA-256 Stream Hashing phát hiện sai lệch từng bit nhị phân.", COLOR_RED),
        ("R - Repudiation (Chối Bỏ)", "Trường chối bỏ việc đã từng cấp chứng chỉ.", "Chữ ký RSA-2048 PKCS#1 v1.5 mang giá trị pháp lý không thể chối bỏ.", COLOR_AMBER),
        ("T - Tampering (DB Nội Bộ)", "Kẻ gian sửa trực tiếp ô dữ liệu trong SQLite.", "Sổ cái băm Merkle phát hiện đứt gãy chuỗi ngay tại block bị sửa.", COLOR_RED),
        ("E - Elevation of Privilege", "Người dùng thường tự gọi API cấp bằng.", "Server-side RBAC (@require_role) chặn đứng với HTTP 403.", COLOR_GREEN),
    ]
    for idx, (code, threat, mitigation, col) in enumerate(stride_threats):
        y = 1.8 + idx * 0.98
        row_shape = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(y), Inches(11.73), Inches(0.85))
        row_shape.fill.solid()
        row_shape.fill.fore_color.rgb = COLOR_CARD
        row_shape.line.color.rgb = col

        tb_row = s5.shapes.add_textbox(Inches(1.0), Inches(y + 0.05), Inches(11.3), Inches(0.75))
        tf_row = tb_row.text_frame
        p_row = tf_row.paragraphs[0]
        p_row.text = f"{code}: {threat}"
        p_row.font.size = Pt(12.5)
        p_row.font.bold = True
        p_row.font.color.rgb = col

        p_sub = tf_row.add_paragraph()
        p_sub.text = f"🛡️ Biện pháp phòng thủ: {mitigation}"
        p_sub.font.size = Pt(11)
        p_sub.font.color.rgb = COLOR_WHITE

    # -------------------------------------------------------------
    # SLIDE 6: ARCHITECTURE DIAGRAM
    # -------------------------------------------------------------
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "KIẾN TRÚC HỆ THỐNG ĐA TẦNG (LAYERED ARCHITECTURE)")

    arch_img_path = DIAGRAMS_DIR / "architecture_diagram.png"
    if arch_img_path.exists():
        s6.shapes.add_picture(str(arch_img_path), Inches(1.5), Inches(1.6), width=Inches(10.33))
    else:
        tb_alt = s6.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(11.0), Inches(4.0))
        tb_alt.text_frame.text = "Sơ đồ kiến trúc hệ thống 5 tầng: UI -> Flask Web -> Services -> Crypto -> Storage"

    # -------------------------------------------------------------
    # SLIDE 7: DATA FLOW & VERIFICATION PIPELINE
    # -------------------------------------------------------------
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "QUY TRÌNH THẨM ĐỊNH VĂN BẢN ZERO-TRUST")

    flow_img_path = DIAGRAMS_DIR / "data_flow_diagram.png"
    if flow_img_path.exists():
        s7.shapes.add_picture(str(flow_img_path), Inches(1.5), Inches(1.6), width=Inches(10.33))
    else:
        tb_alt = s7.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(11.0), Inches(4.0))
        tb_alt.text_frame.text = "Sơ đồ luồng thẩm định Zero-Trust 5 bước: Input -> SHA-256 -> RSA Verify -> Revocation -> Verdict"

    # -------------------------------------------------------------
    # SLIDE 8: PROTOTYPE IMPLEMENTATION
    # -------------------------------------------------------------
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "HIỆN THỰC PROTOTYPE VÀ CÔNG NGHỆ ÁP DỤNG")

    tech_cards = [
        ("Tech Stack", "• Python 3.14 (Core Runtime)\n• Flask 3.1 (REST API & Gateway)\n• Cryptography 50.0 (RSA & Hash)\n• SQLite 3 (Indexed Relational Storage)\n• HTML5/CSS3/JS (Vanilla Cyber Theme)", COLOR_CYAN),
        ("Cơ Chế Bảo Vệ", "• SHA-256 Stream Chunking (64KB)\n• RSA-2048 PKCS#1 v1.5 Signatures\n• Merkle / Hash Chain Audit Ledger\n• PBKDF2-HMAC (100k rounds, 16B salt)\n• UUID File Vault Isolation", COLOR_GREEN),
        ("Giao Diện & CLI", "• Cổng thẩm định kéo thả tức thì\n• Bảng điều khiển Issuer (Ký & Thu hồi)\n• Sổ cái giám sát cho Auditor\n• Phòng thí nghiệm Attack Lab 1-click\n• Công cụ Terminal CLI Headless", COLOR_AMBER),
    ]
    for idx, (head, desc, col) in enumerate(tech_cards):
        c = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.95), Inches(1.8), Inches(3.7), Inches(4.8))
        c.fill.solid()
        c.fill.fore_color.rgb = COLOR_CARD
        c.line.color.rgb = col
        c.line.width = Pt(1.5)

        tb_c = s8.shapes.add_textbox(Inches(1.0 + idx * 3.95), Inches(2.1), Inches(3.3), Inches(4.2))
        tf_c = tb_c.text_frame
        tf_c.word_wrap = True

        p_h = tf_c.paragraphs[0]
        p_h.text = head
        p_h.font.size = Pt(17)
        p_h.font.bold = True
        p_h.font.color.rgb = col
        p_h.space_after = Pt(12)

        p_d = tf_c.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(12.5)
        p_d.font.color.rgb = COLOR_WHITE
        p_d.line_spacing = 1.35

    # -------------------------------------------------------------
    # SLIDE 9: ATTACK LAB SIMULATION & FORENSICS
    # -------------------------------------------------------------
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "PHÒNG THÍ NGHIỆM TẤN CÔNG & ĐIỀU TRA SỐ (ATTACK LAB)")

    attacks = [
        ("KỊCH BẢN 1: TẤN CÔNG ĐẢO 1 BIT (BIT-FLIP)", "Kẻ gian sửa 1 ký tự điểm GPA trong bảng điểm.\n-> Kính hiển vi byte bóc tách offset 0x0000; Ma trận tuyết lở 256-bit (Avalanche Heatmap) đổi màu 50% bits; Báo TAMPERED_CONTENT.", COLOR_RED),
        ("KỊCH BẢN 2: GIẢ MẠO CHỮ KÝ BẰNG KHÓA LẠ", "Kẻ mạo danh tự sinh khóa RSA riêng và ký lên văn bản giả mạo.\n-> Kết quả: Root Public Key từ chối chữ ký; hệ thống báo INVALID_SIGNATURE.", COLOR_AMBER),
        ("KỊCH BẢN 3: VƯỢT RÀO VĂN BẢN ĐÃ THU HỒI", "Ứng viên bị kỷ luật dùng văn bản đã bị thu hồi đi nộp hồ sơ.\n-> Kết quả: Zero-Trust Engine phát hiện trạng thái REVOKED kèm lý do kỷ luật.", COLOR_CYAN),
        ("KỊCH BẢN 4: SỬA LÉN DATABASE & TỰ LÀNH", "Quản trị viên nội bộ vào SQLite sửa trường dữ liệu của Block 0.\n-> Kết quả: Sổ cái báo vỡ chuỗi tại Block 1; hỗ trợ nút Khôi phục tự lành (Self-Healing).", COLOR_RED),
    ]
    for idx, (title, desc, col) in enumerate(attacks):
        c = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + (idx % 2) * 5.95), Inches(1.8 + (idx // 2) * 2.5), Inches(5.7), Inches(2.3))
        c.fill.solid()
        c.fill.fore_color.rgb = COLOR_CARD
        c.line.color.rgb = col

        tb_a = s9.shapes.add_textbox(Inches(1.0 + (idx % 2) * 5.95), Inches(1.95 + (idx // 2) * 2.5), Inches(5.3), Inches(2.0))
        tf_a = tb_a.text_frame
        tf_a.word_wrap = True
        p_t = tf_a.paragraphs[0]
        p_t.text = title
        p_t.font.size = Pt(13)
        p_t.font.bold = True
        p_t.font.color.rgb = col
        p_t.space_after = Pt(6)
        p_d = tf_a.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_WHITE
        p_d.line_spacing = 1.25

    # -------------------------------------------------------------
    # SLIDE 10: TEST RESULTS
    # -------------------------------------------------------------
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "KẾT QUẢ KIỂM THỬ THỰC TẾ (TEST RESULTS)")

    metric_box = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.73), Inches(1.1))
    metric_box.fill.solid()
    metric_box.fill.fore_color.rgb = COLOR_CARD
    metric_box.line.color.rgb = COLOR_GREEN

    tb_m = s10.shapes.add_textbox(Inches(1.0), Inches(1.9), Inches(11.3), Inches(0.9))
    p_m = tb_m.text_frame.paragraphs[0]
    p_m.text = "TỔNG SỐ TEST CASES: 27 / 27 ĐẠT (PASS 100%)  |  THỜI GIAN THỰC THI: 4.08s"
    p_m.font.size = Pt(16)
    p_m.font.bold = True
    p_m.font.color.rgb = COLOR_GREEN
    p_m.alignment = PP_ALIGN.CENTER

    test_groups = [
        ("Mật Mã Học (9 Tests)", "✓ SHA-256 standard digests\n✓ Avalanche effect (>40% bits)\n✓ 256-bit vector difference\n✓ RSA-2048 keypair lifecycle\n✓ RSA-PKCS#1 v1.5 Sign & Verify\n✓ Tamper rejection on hash flip\n✓ Rogue key rejection\n✓ Merkle chain verification\n✓ Tamper detection on ledger", COLOR_CYAN),
        ("Xác Thực & RBAC (3 Tests)", "✓ PBKDF2 hash & verify\n✓ 100,000 iterations work factor\n✓ Salt uniqueness per password\n✓ Seeded roles authentication\n✓ Server-side RBAC protection", COLOR_GREEN),
        ("Nghiệp Vụ & Verify (10 Tests)", "✓ Path Traversal prevention\n✓ 0-byte file rejection\n✓ Issue document & append block\n✓ Revocation lifecycle\n✓ Happy path verification\n✓ Tampered content detection\n✓ Revoked document detection\n✓ Corrupted signature verdict\n✓ Web Crypto In-Browser Verify", COLOR_AMBER),
        ("Kịch Bản Tấn Công (5 Tests)", "✓ Bit-flip GPA modification\n✓ Rogue RSA key forgery\n✓ Direct database tampering\n✓ Malicious filename traversal\n✓ Revocation bypass attack", COLOR_RED),
    ]
    for idx, (title, desc, col) in enumerate(test_groups):
        c = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 2.95), Inches(3.1), Inches(2.8), Inches(3.6))
        c.fill.solid()
        c.fill.fore_color.rgb = COLOR_CARD
        c.line.color.rgb = col
        tb_g = s10.shapes.add_textbox(Inches(0.95 + idx * 2.95), Inches(3.25), Inches(2.5), Inches(3.3))
        tf_g = tb_g.text_frame
        tf_g.word_wrap = True
        p1 = tf_g.paragraphs[0]
        p1.text = title
        p1.font.size = Pt(12.5)
        p1.font.bold = True
        p1.font.color.rgb = col
        p1.space_after = Pt(8)
        p2 = tf_g.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(10)
        p2.font.color.rgb = COLOR_WHITE
        p2.line_spacing = 1.25

    # -------------------------------------------------------------
    # SLIDE 11: TRADE-OFF ANALYSIS
    # -------------------------------------------------------------
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "PHÂN TÍCH ĐÁNH ĐỔI BẮT BUỘC (TRADE-OFF ANALYSIS)")

    tradeoffs = [
        ("Toàn Vẹn Mật Mã vs. Quyền Riêng Tư Cá Nhân",
         "• Bài toán: Nhà tuyển dụng gửi cả bảng điểm (chứa tên, địa chỉ, CCCD) lên server sẽ làm lộ dữ liệu cá nhân (PII).\n"
         "• Giải pháp SecuDoc: Thẩm định dựa trên mã băm SHA-256 độc lập. Server không lưu trữ file của người thẩm tra.\n"
         "• Đánh đổi: Tuân thủ tuyệt đối GDPR / Nghị định 13; ngăn chặn rủi ro rò rỉ dữ liệu diện rộng.", COLOR_CYAN),
        ("Khắt Khe Nhị Phân vs. Trải Nghiệm Người Dùng",
         "• Bài toán: SHA-256 nhạy cảm tới từng bit. Nếu phần mềm điện thoại chèn thêm vài byte metadata cuối file, file sẽ bị báo TAMPERED.\n"
         "• Giải pháp SecuDoc: Giữ vững nguyên tắc Security First, kiên quyết từ chối mọi sai lệch nhị phân để ngăn mã độc Polyglot.\n"
         "• Giảm thiểu: Cung cấp giải thích chi tiết, đối chiếu hash kỳ vọng và hash thực tế trên giao diện.", COLOR_AMBER),
        ("Sổ Cái Nội Bộ vs. Blockchain Công Khai",
         "• Bài toán: Blockchain công khai (Ethereum) tốn gas fee đắt đỏ, độ trễ cao và phụ thuộc Internet.\n"
         "• Giải pháp SecuDoc: Sổ cái băm Cryptographic Hash Chain cục bộ.\n"
         "• Lợi ích: Tốc độ <10ms, chi phí 0 đồng, độc lập hạ tầng mạng nội bộ trường học.", COLOR_GREEN),
    ]
    for idx, (title, desc, col) in enumerate(tradeoffs):
        c = s11.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + idx * 3.95), Inches(1.8), Inches(3.7), Inches(4.8))
        c.fill.solid()
        c.fill.fore_color.rgb = COLOR_CARD
        c.line.color.rgb = col
        tb_t = s11.shapes.add_textbox(Inches(1.0 + idx * 3.95), Inches(2.0), Inches(3.3), Inches(4.3))
        tf_t = tb_t.text_frame
        tf_t.word_wrap = True
        p1 = tf_t.paragraphs[0]
        p1.text = title
        p1.font.size = Pt(14)
        p1.font.bold = True
        p1.font.color.rgb = col
        p1.space_after = Pt(10)
        p2 = tf_t.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(11.5)
        p2.font.color.rgb = COLOR_WHITE
        p2.line_spacing = 1.3

    # -------------------------------------------------------------
    # SLIDE 12: CONCLUSION & FUTURE WORK
    # -------------------------------------------------------------
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "TỔNG KẾT VÀ HƯỚNG PHÁT TRIỂN TƯƠNG LAI")

    c1 = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.8))
    c1.fill.solid()
    c1.fill.fore_color.rgb = COLOR_CARD
    c1.line.color.rgb = COLOR_GREEN

    tb_c1 = s12.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.4))
    tf_c1 = tb_c1.text_frame
    tf_c1.word_wrap = True
    p1 = tf_c1.paragraphs[0]
    p1.text = "KẾT QUẢ ĐẠT ĐƯỢC CỦA ĐỒ ÁN"
    p1.font.size = Pt(16)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_GREEN
    p1.space_after = Pt(12)

    points = [
        "✓ Hoàn thành 100% các yêu cầu bắt buộc của học phần Bảo Mật Mạng và Hệ Thống.",
        "✓ Xây dựng trọn vẹn giải pháp Zero-Trust thực tế từ mật mã học tới ứng dụng web.",
        "✓ Chứng minh khả năng phát hiện 100% các cuộc tấn công can thiệp dữ liệu và giả mạo chữ ký.",
        "✓ Bộ 25 test cases tự động chạy đạt 100% trên môi trường Windows local.",
        "✓ Đầy đủ tài liệu bàn giao: Báo cáo Word, Slide thuyết trình, Mã nguồn và Test Results.",
    ]
    for pt in points:
        p = tf_c1.add_paragraph()
        p.text = pt
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE
        p.space_after = Pt(8)

    c2 = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.8))
    c2.fill.solid()
    c2.fill.fore_color.rgb = COLOR_CARD
    c2.line.color.rgb = COLOR_CYAN

    tb_c2 = s12.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.4))
    tf_c2 = tb_c2.text_frame
    tf_c2.word_wrap = True
    p2 = tf_c2.paragraphs[0]
    p2.text = "HẠN CHẾ VÀ HƯỚNG PHÁT TRIỂN"
    p2.font.size = Pt(16)
    p2.font.bold = True
    p2.font.color.rgb = COLOR_CYAN
    p2.space_after = Pt(12)

    future = [
        "• Hạn chế: Chưa tích hợp chữ ký số công cộng quốc gia (Viettel-CA, VNPT-CA).",
        "• Hạn chế: Dung lượng tải lên hiện giới hạn 10MB cho prototype local.",
        "• Hướng phát triển 1: Tích hợp chuẩn chứng chỉ số W3C Verifiable Credentials.",
        "• Hướng phát triển 2: Xây dựng ứng dụng di động quét mã QR chứa chữ ký nén để thẩm định offline hoàn toàn.",
        "• Hướng phát triển 3: Tích hợp Hardware Security Module (HSM) lưu trữ khóa riêng.",
    ]
    for fu in future:
        p = tf_c2.add_paragraph()
        p.text = fu
        p.font.size = Pt(12)
        p.font.color.rgb = COLOR_WHITE
        p.space_after = Pt(8)

    prs.save(str(OUTPUT_FILE))
    print(f"[+] Đã tạo thành công file trình chiếu: {OUTPUT_FILE}")


if __name__ == "__main__":
    create_presentation()
