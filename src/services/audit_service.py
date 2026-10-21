"""Audit Service for inspecting and cryptographically verifying the immutable ledger."""
from typing import Any
from ..crypto.merkle import verify_audit_chain
from ..models.database import DatabaseManager, get_db

ALLOWED_TAMPER_FIELDS = {"action", "prev_block_hash", "doc_uuid", "payload_hash", "timestamp"}


class AuditService:
    """Manages query operations and cryptographic integrity checks over the Audit Ledger."""

    def __init__(self, db_manager: DatabaseManager | None = None):
        self.db = db_manager or get_db()
        # In-memory snapshot storage to allow accurate restoration of ANY block index
        self._tamper_snapshots: dict[int, dict[str, Any]] = {}

    def get_all_audit_blocks(self) -> list[dict[str, Any]]:
        """Retrieve all blocks in the ledger ordered by block index."""
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC;")
            return [dict(row) for row in cursor.fetchall()]

    def get_block_by_index(self, block_index: int) -> dict[str, Any] | None:
        """Fetch a specific block by its sequence index."""
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_blocks WHERE block_index = ?;", (block_index,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def verify_chain_integrity(self, require_genesis: bool = False) -> dict[str, Any]:
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
                "message": "Sổ cái rỗng (hệ thống chưa khởi tạo khối nào)"
            }

        is_valid, broken_idx, reason = verify_audit_chain(blocks, require_genesis=require_genesis)
        if is_valid:
            return {
                "is_valid": True,
                "total_blocks": len(blocks),
                "broken_at_block_index": None,
                "message": f"Toàn bộ {len(blocks)} khối trong sổ cái đều TOÀN VẸN và LIÊN TỤC về mặt mật mã học."
            }
        else:
            return {
                "status": "TAMPERED",
                "is_valid": False,
                "total_blocks": len(blocks),
                "broken_at_block_index": broken_idx,
                "message": f"PHÁT HIỆN CAN THIỆP SỔ CÁI: {reason}"
            }

    def simulate_database_tamper(
        self,
        block_index: int,
        field_to_alter: str = "action",
        malicious_value: str = "TAMPERED_ACTION"
    ) -> bool:
        """
        Simulate an internal malicious insider directly altering a field in SQLite.
        Saves a snapshot of the original block state so it can be restored accurately later.
        Used exclusively in attack testing and security demonstrations.
        """
        if field_to_alter not in ALLOWED_TAMPER_FIELDS:
            raise ValueError(f"Trường '{field_to_alter}' không nằm trong danh sách được phép mô phỏng can thiệp.")

        original_block = self.get_block_by_index(block_index)
        if not original_block:
            return False

        # Save snapshot for accurate restoration
        if block_index not in self._tamper_snapshots:
            self._tamper_snapshots[block_index] = original_block.copy()

        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            query = f"UPDATE audit_blocks SET {field_to_alter} = ? WHERE block_index = ?;"
            cursor.execute(query, (malicious_value, block_index))
            return cursor.rowcount > 0

    def restore_database_block(
        self,
        block_index: int,
        field_to_restore: str | None = None,
        original_value: str | None = None
    ) -> bool:
        """
        Restore a tampered block back to its authentic state.
        Uses the saved snapshot if available, allowing reliable restoration of ANY block index.
        """
        snapshot = self._tamper_snapshots.get(block_index)

        with self.db.connection_context() as conn:
            cursor = conn.cursor()

            if snapshot:
                # Restore from recorded original snapshot
                if field_to_restore and field_to_restore in snapshot:
                    val = snapshot[field_to_restore]
                    query = f"UPDATE audit_blocks SET {field_to_restore} = ? WHERE block_index = ?;"
                    cursor.execute(query, (val, block_index))
                else:
                    cursor.execute("""
                        UPDATE audit_blocks
                        SET prev_block_hash = ?, timestamp = ?, action = ?, doc_uuid = ?, payload_hash = ?, block_hash = ?
                        WHERE block_index = ?;
                    """, (
                        snapshot["prev_block_hash"], snapshot["timestamp"], snapshot["action"],
                        snapshot["doc_uuid"], snapshot["payload_hash"], snapshot["block_hash"],
                        block_index
                    ))
                self._tamper_snapshots.pop(block_index, None)
                return cursor.rowcount > 0

            # Fallback if no snapshot was tracked
            field = field_to_restore or "action"
            val = original_value if original_value is not None else ("GENESIS" if block_index == 0 else "ISSUE")
            query = f"UPDATE audit_blocks SET {field} = ? WHERE block_index = ?;"
            cursor.execute(query, (val, block_index))
            return cursor.rowcount > 0

