"""Command-Line Interface for SecuDoc: Verification, Issuance, and Attack Simulation."""
import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
from ..crypto.keys import KeyManager
from ..crypto.hashing import calculate_bytes_hash, count_bit_differences
from ..models.database import DatabaseManager, get_db
from ..services.doc_service import DocumentService
from ..services.audit_service import AuditService
from ..services.verify_engine import VerificationEngine


def cmd_verify(args):
    """Verify a document file via CLI."""
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"[!] Lỗi: Tệp '{args.file}' không tồn tại!")
        sys.exit(1)

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    engine = VerificationEngine()
    result = engine.verify_document(file_bytes, claimed_uuid=args.uuid)

    print("\n" + "=" * 65)
    print(f"[*] KẾT QUẢ THẨM ĐỊNH SECUDOC (ZERO-TRUST)")
    print("=" * 65)
    print(f"  Trạng Thái     : {result['status']}")
    print(f"  Kết Luận       : {result['verdict_title']}")
    print(f"  Giải Thích     : {result['explanation']}")
    print(f"  Mã Băm Tệp     : {result['computed_hash']}")
    print(f"  Chữ Ký Số RSA  : {'HỢP LỆ' if result['signature_valid'] else 'KHÔNG HỢP LỆ'}")
    if result["document"]:
        doc = result["document"]
        print("-" * 65)
        print(f"  Tiêu Đề        : {doc['title']}")
        print(f"  Người Nhận     : {doc['recipient_name']}")
        print(f"  Cơ Quan Ban Hành: {doc['issuer_name']}")
        print(f"  Thời Điểm Ký   : {doc['issued_at']}")
    print("=" * 65 + "\n")


def cmd_issue(args):
    """Issue a document via CLI."""
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"[!] Lỗi: Tệp '{args.file}' không tồn tại!")
        sys.exit(1)

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    doc_svc = DocumentService()
    doc = doc_svc.issue_document(
        issuer_id=1, # Default issuer
        title=args.title,
        recipient_name=args.recipient,
        doc_type=args.type,
        file_bytes=file_bytes,
        original_filename=file_path.name
    )

    print("\n" + "=" * 65)
    print(f"[+] PHÁT HÀNH VÀ KÝ SỐ VĂN BẢN THÀNH CÔNG")
    print("=" * 65)
    print(f"  Mã UUID        : {doc['doc_uuid']}")
    print(f"  Tiêu Đề        : {doc['title']}")
    print(f"  Người Nhận     : {doc['recipient_name']}")
    print(f"  Mã Băm SHA-256 : {doc['doc_hash']}")
    print(f"  Chữ Ký Số RSA  : {doc['signature'][:48]}...")
    print(f"  Đã đóng vào Block Sổ cái thành công!")
    print("=" * 65 + "\n")


def cmd_audit(args):
    """Inspect and mathematically verify audit ledger integrity."""
    audit_svc = AuditService()
    status = audit_svc.verify_chain_integrity()
    blocks = audit_svc.get_all_audit_blocks()

    print("\n" + "=" * 65)
    print(f"[*] KIỂM TOÁN TÍNH TOÀN VẸN SỔ CÁI BẤT BIẾN")
    print("=" * 65)
    print(f"  Tổng Số Khối   : {status['total_blocks']}")
    print(f"  Toàn Vẹn       : {'TOÀN VẸN 100%' if status['is_valid'] else 'BỊ VỠ CHUỖI'}")
    print(f"  Thông Điệp     : {status['message']}")
    print("-" * 65)
    for b in blocks:
        print(f"  Block #{b['block_index']} [{b['action']}] UUID: {b['doc_uuid'][:8]}... Hash: {b['block_hash'][:16]}...")
    print("=" * 65 + "\n")


def cmd_attack_demo(args):
    """Run headless Bit-Flip Tampering Attack demonstration."""
    sample_text = (
        b"TRUONG DAI HOC CONG NGHE THONG TIN - BANG TOT NGHIEP\n"
        b"Sinh vien: NGUYEN VAN A - Xep loai: XUAT SAC - Diem GPA: 3.90\n"
    )
    original_hash = calculate_bytes_hash(sample_text)

    # Flip 1 bit in first byte
    tampered_bytes = bytearray(sample_text)
    tampered_bytes[0] ^= 0x01
    tampered_hash = calculate_bytes_hash(bytes(tampered_bytes))

    diff_bits, total_bits, pct = count_bit_differences(original_hash, tampered_hash)

    print("\n" + "=" * 65)
    print(f"[!] MÔ PHỎNG TẤN CÔNG CAN THIỆP 1 BIT NHỊ PHÂN (BIT-FLIP ATTACK)")
    print("=" * 65)
    print(f"  Nội dung gốc       : {sample_text.decode('utf-8').strip()}")
    print(f"  Mã băm gốc SHA-256 : {original_hash}")
    print("-" * 65)
    print(f"  Đã đảo đúng 1 bit ở byte đầu tiên.")
    print(f"  Mã băm mới SHA-256 : {tampered_hash}")
    print(f"  Hiệu ứng tuyết lở  : {diff_bits}/{total_bits} bits khác biệt ({pct:.2f}%)")
    print("-" * 65)
    print(f"  -> Kết luận: Hai mã băm hoàn toàn khác biệt. Hệ thống Zero-Trust")
    print(f"     lập tức phát hiện và từ chối tài liệu với trạng thái TAMPERED_CONTENT!")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(description="SecuDoc CLI - Hệ thống Thẩm định Văn bản Số Chống Giả mạo")
    subparsers = parser.add_subparsers(dest="command", help="Lệnh thực thi")

    # verify
    p_verify = subparsers.add_parser("verify", help="Thẩm định tệp văn bản")
    p_verify.add_argument("file", help="Đường dẫn tới tệp cần thẩm định")
    p_verify.add_argument("--uuid", help="Mã UUID chứng nhận đối soát", default=None)

    # issue
    p_issue = subparsers.add_parser("issue", help="Phát hành và ký số văn bản")
    p_issue.add_argument("file", help="Đường dẫn tới tệp gốc")
    p_issue.add_argument("--title", required=True, help="Tiêu đề văn bản")
    p_issue.add_argument("--recipient", required=True, help="Tên người nhận")
    p_issue.add_argument("--type", default="CERTIFICATE", help="Loại văn bản (DIPLOMA, TRANSCRIPT...)")

    # audit
    subparsers.add_parser("audit", help="Kiểm toán toàn vẹn sổ cái băm")

    # attack-demo
    subparsers.add_parser("attack-demo", help="Chạy mô phỏng tấn công can thiệp dữ liệu 1-bit")

    args = parser.parse_args()
    if args.command == "verify":
        cmd_verify(args)
    elif args.command == "issue":
        cmd_issue(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "attack-demo":
        cmd_attack_demo(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
