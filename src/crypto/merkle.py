"""Tamper-Evident Hash-Chain and Merkle Audit Ledger Engine."""
import hashlib
from typing import Any

GENESIS_PREV_HASH = "0" * 64


def calculate_block_hash(
    block_index: int,
    prev_block_hash: str,
    timestamp: str,
    action: str,
    doc_uuid: str,
    payload_hash: str
) -> str:
    """
    Calculate the cryptographic block hash using canonical serialization and SHA-256.
    Ensures that any alteration to any field produces a completely broken block hash.
    """
    canonical_repr = f"{block_index}|{prev_block_hash}|{timestamp}|{action}|{doc_uuid}|{payload_hash}"
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


def verify_audit_chain(blocks: list[dict[str, Any]]) -> tuple[bool, int | None, str | None]:
    """
    Verify the cryptographic integrity of the entire audit chain.
    Returns:
        (is_valid, broken_at_index, reason)
    """
    if not blocks:
        return True, None, None

    for idx, block in enumerate(blocks):
        # 1. Verify index sequence
        if block["block_index"] != idx:
            return False, idx, f"Chỉ mục block không liên tục: kỳ vọng {idx}, nhận được {block['block_index']}"

        # 2. Verify previous hash pointer
        if idx == 0:
            if block["prev_block_hash"] != GENESIS_PREV_HASH:
                return False, 0, f"Genesis block có prev_block_hash không hợp lệ: {block['prev_block_hash']}"
        else:
            prev_block = blocks[idx - 1]
            if block["prev_block_hash"] != prev_block["block_hash"]:
                return (
                    False,
                    idx,
                    f"Đứt gãy liên kết chuỗi tại block {idx}: prev_block_hash ({block['prev_block_hash'][:16]}...) "
                    f"không khớp với hash block trước đó ({prev_block['block_hash'][:16]}...)"
                )

        # 3. Recalculate block hash and compare with stored hash
        computed_hash = calculate_block_hash(
            block_index=block["block_index"],
            prev_block_hash=block["prev_block_hash"],
            timestamp=str(block["timestamp"]),
            action=block["action"],
            doc_uuid=block["doc_uuid"],
            payload_hash=block["payload_hash"]
        )

        if computed_hash != block["block_hash"]:
            return (
                False,
                idx,
                f"Dữ liệu bên trong block {idx} đã bị can thiệp trái phép! "
                f"Mã băm lưu trữ: {block['block_hash'][:16]}..., Mã băm tính toán lại: {computed_hash[:16]}..."
            )

    return True, None, None
