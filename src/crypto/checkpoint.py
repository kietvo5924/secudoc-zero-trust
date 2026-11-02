"""Signed Checkpoint Engine for Independent Audit Ledger Verification.

Implements cryptographically signed checkpoints for the sequential hash chain,
providing an authoritative, independent reference anchor outside the primary database.
Guarantees tamper-evidence even if an attacker possesses full database write access
and re-calculates all intermediate block hashes (Full-Chain Rewrite Attack).
"""
import json
import hashlib
from datetime import datetime, timezone
from typing import Any
from .signature import sign_hash, verify_signature
from .keys import KeyManager


CHECKPOINT_VERSION = "1.0"


def build_checkpoint_canonical_payload(
    version: str,
    sequence: int,
    last_block_index: int,
    total_blocks: int,
    last_block_hash: str,
    prev_checkpoint_hash: str | None,
    root_key_fingerprint: str,
    timestamp: str
) -> str:
    """
    Build canonical pipe-delimited string of the checkpoint for signature generation & verification.
    Format:
        CHECKPOINT_CANONICAL_V1|version|sequence|last_block_index|total_blocks|last_block_hash|prev_checkpoint_hash|root_key_fingerprint|timestamp
    """
    prev_cp_str = prev_checkpoint_hash.strip() if prev_checkpoint_hash else "NONE"
    return (
        f"CHECKPOINT_CANONICAL_V1|{version}|{sequence}|{last_block_index}|"
        f"{total_blocks}|{last_block_hash}|{prev_cp_str}|{root_key_fingerprint}|{timestamp}"
    )


def calculate_checkpoint_hash(checkpoint_data: dict[str, Any]) -> str:
    """Calculate SHA-256 digest of the canonical checkpoint payload."""
    canonical_str = build_checkpoint_canonical_payload(
        version=checkpoint_data.get("version", CHECKPOINT_VERSION),
        sequence=checkpoint_data["sequence"],
        last_block_index=checkpoint_data["last_block_index"],
        total_blocks=checkpoint_data["total_blocks"],
        last_block_hash=checkpoint_data["last_block_hash"],
        prev_checkpoint_hash=checkpoint_data.get("prev_checkpoint_hash"),
        root_key_fingerprint=checkpoint_data["root_key_fingerprint"],
        timestamp=checkpoint_data["timestamp"]
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def create_signed_checkpoint(
    blocks: list[dict[str, Any]],
    private_key_pem: bytes,
    public_key_pem: bytes,
    sequence: int = 1,
    prev_checkpoint_hash: str | None = None
) -> dict[str, Any]:
    """
    Generate and cryptographically sign a checkpoint for the current state of audit blocks.
    Raises ValueError if blocks list is empty.
    """
    if not blocks:
        raise ValueError("Không thể tạo checkpoint từ sổ cái trống rỗng.")

    last_block = blocks[-1]
    last_block_index = last_block["block_index"]
    last_block_hash = last_block["block_hash"]
    total_blocks = len(blocks)
    now_str = datetime.now(timezone.utc).isoformat()

    key_mgr = KeyManager()
    root_key_fingerprint = key_mgr.get_public_key_fingerprint(public_key_pem)

    canonical_str = build_checkpoint_canonical_payload(
        version=CHECKPOINT_VERSION,
        sequence=sequence,
        last_block_index=last_block_index,
        total_blocks=total_blocks,
        last_block_hash=last_block_hash,
        prev_checkpoint_hash=prev_checkpoint_hash,
        root_key_fingerprint=root_key_fingerprint,
        timestamp=now_str
    )
    checkpoint_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    signature_b64 = sign_hash(checkpoint_digest, private_key_pem)

    checkpoint = {
        "version": CHECKPOINT_VERSION,
        "sequence": sequence,
        "last_block_index": last_block_index,
        "total_blocks": total_blocks,
        "last_block_hash": last_block_hash,
        "prev_checkpoint_hash": prev_checkpoint_hash,
        "root_key_fingerprint": root_key_fingerprint,
        "timestamp": now_str,
        "checkpoint_hash": checkpoint_digest,
        "signature": signature_b64
    }
    return checkpoint


def verify_checkpoint_signature(
    checkpoint_data: dict[str, Any],
    public_key_pem: bytes
) -> tuple[bool, str]:
    """
    Verify the RSA cryptographic signature of a checkpoint file.
    Returns: (is_valid, message)
    """
    required_fields = [
        "version", "sequence", "last_block_index", "total_blocks",
        "last_block_hash", "root_key_fingerprint", "timestamp", "signature"
    ]
    for field in required_fields:
        if field not in checkpoint_data:
            return False, f"Checkpoint thiếu trường bắt buộc: {field}"

    key_mgr = KeyManager()
    actual_fingerprint = key_mgr.get_public_key_fingerprint(public_key_pem)
    if actual_fingerprint != checkpoint_data["root_key_fingerprint"]:
        return (
            False,
            f"Fingerprint khóa công khai không khớp! Kỳ vọng: {checkpoint_data['root_key_fingerprint']}, "
            f"Thực tế khóa cung cấp: {actual_fingerprint}"
        )

    canonical_str = build_checkpoint_canonical_payload(
        version=checkpoint_data.get("version", CHECKPOINT_VERSION),
        sequence=checkpoint_data["sequence"],
        last_block_index=checkpoint_data["last_block_index"],
        total_blocks=checkpoint_data["total_blocks"],
        last_block_hash=checkpoint_data["last_block_hash"],
        prev_checkpoint_hash=checkpoint_data.get("prev_checkpoint_hash"),
        root_key_fingerprint=checkpoint_data["root_key_fingerprint"],
        timestamp=checkpoint_data["timestamp"]
    )
    checkpoint_digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    is_sig_valid = verify_signature(
        public_key_pem,
        checkpoint_digest,
        checkpoint_data["signature"]
    )
    if not is_sig_valid:
        return False, "Chữ ký số của Checkpoint KHÔNG HỢP LỆ hoặc checkpoint đã bị chỉnh sửa nội dung!"

    return True, "Chữ ký số của Checkpoint hoàn toàn hợp lệ."


def verify_ledger_against_checkpoint(
    blocks: list[dict[str, Any]],
    checkpoint_data: dict[str, Any],
    public_key_pem: bytes
) -> dict[str, Any]:
    """
    Perform independent audit ledger verification against a trusted signed checkpoint:
    1. Verify checkpoint signature & root key fingerprint.
    2. Check for database rollback: len(blocks) < checkpoint['total_blocks'].
    3. Check for full-chain rewrite: block at checkpoint['last_block_index'] does not match checkpoint['last_block_hash'].
    Returns detailed audit report dictionary.
    """
    sig_ok, sig_msg = verify_checkpoint_signature(checkpoint_data, public_key_pem)
    if not sig_ok:
        return {
            "is_valid": False,
            "status": "CHECKPOINT_SIGNATURE_INVALID",
            "message": f"Checkpoint không hợp lệ: {sig_msg}",
            "checkpoint_sequence": checkpoint_data.get("sequence"),
            "expected_hash": checkpoint_data.get("last_block_hash"),
            "actual_hash": None,
            "block_index": checkpoint_data.get("last_block_index")
        }

    cp_last_index = checkpoint_data["last_block_index"]
    cp_total_blocks = checkpoint_data["total_blocks"]
    cp_last_hash = checkpoint_data["last_block_hash"]

    # 1. Rollback Detection
    if len(blocks) < cp_total_blocks:
        return {
            "is_valid": False,
            "status": "HISTORY_ROLLBACK_DETECTED",
            "message": (
                f"CẢNH BÁO NGUY HIỂM: Phát hiện khôi phục trạng thái cũ (Database Rollback)! "
                f"Sổ cái hiện tại chỉ có {len(blocks)} khối, nhưng Checkpoint #{checkpoint_data['sequence']} "
                f"đã từng xác nhận hệ thống có {cp_total_blocks} khối."
            ),
            "checkpoint_sequence": checkpoint_data["sequence"],
            "expected_total_blocks": cp_total_blocks,
            "actual_total_blocks": len(blocks),
            "expected_hash": cp_last_hash,
            "actual_hash": None,
            "block_index": cp_last_index
        }

    # Find the block corresponding to the checkpoint index
    matching_block = None
    for b in blocks:
        if b["block_index"] == cp_last_index:
            matching_block = b
            break

    if not matching_block:
        return {
            "is_valid": False,
            "status": "CHECKPOINT_BLOCK_MISSING",
            "message": f"Không tìm thấy khối chỉ mục {cp_last_index} được chỉ định trong Checkpoint.",
            "checkpoint_sequence": checkpoint_data["sequence"],
            "expected_hash": cp_last_hash,
            "actual_hash": None,
            "block_index": cp_last_index
        }

    # 2. Full-Chain Rewrite Detection
    if matching_block["block_hash"] != cp_last_hash:
        return {
            "is_valid": False,
            "status": "FULL_CHAIN_REWRITE_DETECTED",
            "message": (
                f"PHÁT HIỆN TẤN CÔNG VIẾT LẠI LỊCH SỬ SỔ CÁI (FULL-CHAIN REWRITE ATTACK)! "
                f"Khối index {cp_last_index} trong database hiện tại có hash: {matching_block['block_hash'][:16]}..., "
                f"nhưng Checkpoint #{checkpoint_data['sequence']} độc lập đã xác nhận hash phải là: {cp_last_hash[:16]}..."
            ),
            "checkpoint_sequence": checkpoint_data["sequence"],
            "expected_hash": cp_last_hash,
            "actual_hash": matching_block["block_hash"],
            "block_index": cp_last_index
        }

    return {
        "is_valid": True,
        "status": "CHECKPOINT_VERIFIED",
        "message": (
            f"XÁC MINH CHECKPOINT THÀNH CÔNG: Sổ cái khớp chính xác 100% với mốc Checkpoint #{checkpoint_data['sequence']} "
            f"(Khối {cp_last_index}, Hash: {cp_last_hash[:16]}...). Chữ ký số kiểm toán hợp lệ."
        ),
        "checkpoint_sequence": checkpoint_data["sequence"],
        "expected_hash": cp_last_hash,
        "actual_hash": matching_block["block_hash"],
        "block_index": cp_last_index
    }
