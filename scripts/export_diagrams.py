"""Export High-Resolution Visual Architecture & Threat Diagrams using Matplotlib."""
import os
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import matplotlib.pyplot as plt
import matplotlib.patches as patches

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "diagrams"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def draw_architecture_diagram():
    """Generate high-res layered system architecture diagram."""
    fig, ax = plt.subplots(figsize=(12, 8), dpi=200)
    fig.patch.set_facecolor("#080c16")
    ax.set_facecolor("#080c16")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Title
    ax.text(50, 96, "KIẾN TRÚC HỆ THỐNG XÁC MINH VĂN BẢN SỐ SECUDOC", 
            ha="center", va="center", color="#00e5ff", fontsize=15, weight="bold")
    ax.text(50, 92, "Thiết kế Đa Tầng Bảo Mật (Layered Zero-Trust Architecture)", 
            ha="center", va="center", color="#8fa0c0", fontsize=10)

    layers = [
        ("TẦNG TRÌNH DIỄN (CLIENT / UI)", 
         ["Cổng Thẩm Định Độc Lập", "Bảng Điều Khiển Issuer", "Phòng Thí Nghiệm Attack Lab"], 
         78, "#00e5ff", "#0d2238"),
        ("TẦNG DỊCH VỤ WEB (FLASK APPLICATION)", 
         ["Security Headers (CSP, Nosniff)", "Input & Size Sanitizer (Max 10MB)", "Server-side RBAC Enforcement"], 
         60, "#7c4dff", "#1a1236"),
        ("TẦNG DỊCH VỤ NGHIỆP VỤ (SERVICES LAYER)", 
         ["Auth Service (PBKDF2-HMAC)", "Document Service (Issue/Revoke)", "Zero-Trust Verify Engine", "Audit Service (Ledger)"], 
         42, "#00e676", "#0d281a"),
        ("TẦNG ĐỘNG CƠ MẬT MÃ CORE (CRYPTO ENGINE)", 
         ["RSA-2048 Key Vault", "SHA-256 Stream Hashing", "RSA-PKCS#1 v1.5 Signatures", "Merkle Hash Chain Engine"], 
         24, "#ffab00", "#2d2008"),
        ("TẦNG LƯU TRỮ VÀ DỮ LIỆU AN TOÀN (STORAGE LAYER)", 
         ["SQLite Database (secudoc.db)", "Key Store (data/keys/*.pem)", "Isolated File Vault (data/uploads)"], 
         6, "#ff1744", "#2d0d14"),
    ]

    for title, items, y_pos, border_col, bg_col in layers:
        # Layer Box
        rect = patches.FancyBboxPatch((5, y_pos), 90, 14, boxstyle="round,pad=0.8,rounding_size=1.5",
                                     edgecolor=border_col, facecolor=bg_col, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(8, y_pos + 10.5, title, color=border_col, fontsize=10, weight="bold")

        # Sub items
        num_items = len(items)
        item_width = 82 / num_items
        for idx, item in enumerate(items):
            item_x = 8 + idx * item_width
            sub_rect = patches.FancyBboxPatch((item_x, y_pos + 2), item_width - 2, 6.5,
                                              boxstyle="round,pad=0.4,rounding_size=0.8",
                                              edgecolor=border_col, facecolor="#080c16", linewidth=0.8, alpha=0.9)
            ax.add_patch(sub_rect)
            ax.text(item_x + (item_width - 2) / 2, y_pos + 5.2, item, color="#ffffff",
                    fontsize=8, ha="center", va="center", weight="medium")

    # Connective arrows
    for y_arrow in [77, 59, 41, 23]:
        ax.annotate("", xy=(50, y_arrow - 1), xytext=(50, y_arrow + 1),
                    arrowprops=dict(arrowstyle="->", color="#00e5ff", lw=1.8))

    output_path = OUTPUT_DIR / "architecture_diagram.png"
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    print(f"[+] Đã xuất sơ đồ kiến trúc: {output_path}")


def draw_data_flow_diagram():
    """Generate high-res data flow & verification sequence diagram."""
    fig, ax = plt.subplots(figsize=(12, 7), dpi=200)
    fig.patch.set_facecolor("#080c16")
    ax.set_facecolor("#080c16")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    ax.text(50, 95, "QUY TRÌNH XÁC MINH ZERO-TRUST VÀ LUỒNG DỮ LIỆU", 
            ha="center", va="center", color="#00e5ff", fontsize=15, weight="bold")
    ax.text(50, 90, "Nguyên tắc: Không tin cậy đầu vào - Thẩm định toán học độc lập", 
            ha="center", va="center", color="#8fa0c0", fontsize=10)

    steps = [
        ("1. Tệp Đầu Vào\n(Untrusted Input)", 8, 55, "#ff1744"),
        ("2. Băm Phân Mảnh\n(SHA-256 Digest)", 28, 55, "#ffab00"),
        ("3. Đối Soát Khóa\n(RSA-2048 Verify)", 48, 55, "#7c4dff"),
        ("4. Kiểm Tra Thu Hồi\n(Revocation List)", 68, 55, "#00e5ff"),
        ("5. Kết Luận\n(Authentic Verdict)", 88, 55, "#00e676"),
    ]

    for title, x, y, col in steps:
        box = patches.FancyBboxPatch((x - 7, y - 10), 14, 20, boxstyle="round,pad=0.5,rounding_size=1.2",
                                     edgecolor=col, facecolor="#0d1527", linewidth=2)
        ax.add_patch(box)
        ax.text(x, y, title, ha="center", va="center", color="#fff", fontsize=8.5, weight="bold")

    # Arrows between boxes
    for idx in range(len(steps) - 1):
        x1 = steps[idx][1] + 7
        x2 = steps[idx + 1][1] - 7
        ax.annotate("", xy=(x2, 55), xytext=(x1, 55),
                    arrowprops=dict(arrowstyle="->", color="#00e5ff", lw=2.0))

    # Bottom explanations
    explanations = [
        "Tệp PDF/DOCX do ứng viên gửi; có thể đã bị sửa 1 ký tự điểm hoặc con dấu giả.",
        "Đọc 64KB/chunk, tính ra chuỗi 64 ký tự hex. Dù sửa 1 bit, hash đổi 50% ngay.",
        "Dùng Root Public Key xác minh chữ ký của trường. Khóa lạ lập tức bị từ chối.",
        "Tra cứu cơ sở dữ liệu và sổ cái: Nếu tài liệu bị thu hồi kỷ luật, trả về REVOKED.",
        "Chỉ khi qua cả 4 bước toán học, tài liệu mới được xác nhận 100% chính gốc.",
    ]
    for idx, (title, x, y, col) in enumerate(steps):
        ax.text(x, 28, explanations[idx], ha="center", va="top", color="#8fa0c0", fontsize=7.5,
                wrap=True, bbox=dict(boxstyle="square,pad=0.4", fc="#080c16", ec=col, lw=0.8))

    output_path = OUTPUT_DIR / "data_flow_diagram.png"
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    print(f"[+] Đã xuất sơ đồ luồng dữ liệu: {output_path}")


if __name__ == "__main__":
    draw_architecture_diagram()
    draw_data_flow_diagram()
