"""Tamper-Evident Cryptographic Hash-Chain Audit Ledger Engine.

Implements a sequential cryptographic hash-chain where each block's digest
cryptographically seals the previous block's digest, timestamp, action, and payload.
Provides mathematical tamper-evidence for academic and prototype demonstration.
"""
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
    Calculate the cryptographic block hash using canonical pipe serialization and SHA-256.
    Ensures that any alteration to any field produces a completely broken block hash.
    """
    canonical_repr = f"{block_index}|{prev_block_hash}|{timestamp}|{action}|{doc_uuid}|{payload_hash}"
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


def verify_audit_chain(
    blocks: list[dict[str, Any]],
    require_genesis: bool = False
) -> tuple[bool, int | None, str | None]:
    """
    Verify the cryptographic integrity of the entire audit hash chain.

    Checks:
    1. Ledger emptiness vs requirement (an empty ledger is rejected if require_genesis is True).
    2. Block index continuity (0, 1, 2, ...).
    3. Genesis block integrity (prev_block_hash must be all zeros, action must be GENESIS).
    4. Previous block hash pointer matching (prev_block_hash == prev_block['block_hash']).
    5. Block content recalculation (computed block_hash == stored block_hash).

    Returns:
        (is_valid, broken_at_index, reason)
    """
    if not blocks:
        if require_genesis:
            return False, 0, "Sổ cái trống rỗng, không tìm thấy khối Genesis khởi tạo hệ thống"
        return True, None, None

    for idx, block in enumerate(blocks):
        # 1. Verify index sequence
        if block["block_index"] != idx:
            return False, idx, f"Chỉ mục block không liên tục: kỳ vọng {idx}, nhận được {block['block_index']}"

        # 2. Verify previous hash pointer and genesis action
        if idx == 0:
            if block["prev_block_hash"] != GENESIS_PREV_HASH:
                return False, 0, f"Genesis block có prev_block_hash không hợp lệ: {block['prev_block_hash']}"
            if block.get("action") != "GENESIS":
                return False, 0, f"Khối đầu tiên (index 0) bắt buộc phải là hành động GENESIS, nhận được: {block.get('action')}"
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


def get_chain_head_hash(blocks: list[dict[str, Any]]) -> str | None:
    """
    Return the latest block hash (the head/tip of the hash chain) for checkpoint comparison.
    Note: In this prototype, this provides the cryptographic head digest used for threat simulation
    (TC-ATTACK-07). An automated, independent external anchoring service is not currently operated in runtime.
    """
    if not blocks:
        return None
    return blocks[-1]["block_hash"]

