"""Audit Service for inspecting and cryptographically verifying the immutable ledger."""
from typing import Any
from ..crypto.merkle import verify_audit_chain
from ..models.database import DatabaseManager, get_db


class AuditService:
    """Manages query operations and cryptographic integrity checks over the Audit Ledger."""

    def __init__(self, db_manager: DatabaseManager | None = None):
        self.db = db_manager or get_db()

    def get_all_audit_blocks(self) -> list[dict[str, Any]]:
        """Retrieve all blocks in the ledger ordered by block index."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC;")
            return [dict(row) for row in cursor.fetchall()]

    def verify_chain_integrity(self) -> dict[str, Any]:
        """
        Verify the mathematical integrity of the entire hash chain from Genesis block onwards.
        Returns:
            {
                "is_valid": bool,
                "total_blocks": int,
                "broken_at_block_index": int | None,
                "message": str
            }
        """
        blocks = self.get_all_audit_blocks()
        if not blocks:
            return {
                "is_valid": True,
                "total_blocks": 0,
                "broken_at_block_index": None,
                "message": "Sổ cái rỗng"
            }

        is_valid, broken_idx, reason = verify_audit_chain(blocks)
        if is_valid:
            return {
                "is_valid": True,
                "total_blocks": len(blocks),
                "broken_at_block_index": None,
                "message": f"Toàn bộ {len(blocks)} khối trong sổ cái đều TOÀN VẸN và LIÊN TỤC về mặt mật mã học."
            }
        else:
            return {
                "is_valid": False,
                "total_blocks": len(blocks),
                "broken_at_block_index": broken_idx,
                "message": f"PHÁT HIỆN CAN THIỆP SỔ CÁI: {reason}"
            }

    def simulate_database_tamper(self, block_index: int, field_to_alter: str = "action", malicious_value: str = "TAMPERED_ACTION") -> bool:
        """
        Simulate an internal malicious insider directly altering a field in SQLite.
        Used exclusively in attack testing and security demonstrations.
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            query = f"UPDATE audit_blocks SET {field_to_alter} = ? WHERE block_index = ?;"
            cursor.execute(query, (malicious_value, block_index))
            conn.commit()
            return cursor.rowcount > 0

    def restore_database_block(self, block_index: int, field_to_restore: str = "action", original_value: str = "GENESIS") -> bool:
        """
        Restore a tampered block back to its authentic state for repeated live demonstrations.
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            query = f"UPDATE audit_blocks SET {field_to_restore} = ? WHERE block_index = ?;"
            cursor.execute(query, (original_value, block_index))
            conn.commit()
            return cursor.rowcount > 0
