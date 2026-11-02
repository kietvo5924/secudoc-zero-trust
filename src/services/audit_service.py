import json
from ..crypto.checkpoint import create_signed_checkpoint, verify_ledger_against_checkpoint, calculate_checkpoint_hash
from ..crypto.merkle import calculate_block_hash
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
            if require_genesis:
                return {
                    "status": "TAMPERED",
                    "is_valid": False,
                    "total_blocks": 0,
                    "broken_at_block_index": 0,
                    "message": "PHÁT HIỆN CAN THIỆP SỔ CÁI: Sổ cái trống rỗng, không tìm thấy khối Genesis khởi tạo hệ thống"
                }
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

    def create_and_store_checkpoint(
        self,
        created_by: int,
        private_key_pem: bytes,
        public_key_pem: bytes
    ) -> dict[str, Any]:
        """
        Generate and persist a signed checkpoint for the current ledger state.
        Fails if the ledger is invalid or empty.
        """
        integrity = self.verify_chain_integrity(require_genesis=True)
        if not integrity["is_valid"]:
            raise ValueError(f"Không thể tạo Checkpoint vì sổ cái không hợp lệ: {integrity['message']}")

        blocks = self.get_all_audit_blocks()
        if not blocks:
            raise ValueError("Không thể tạo Checkpoint khi sổ cái rỗng.")

        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sequence, checkpoint_json FROM checkpoints ORDER BY sequence DESC LIMIT 1;")
            last_cp = cursor.fetchone()
            seq = (last_cp["sequence"] + 1) if last_cp else 1
            prev_cp_hash = None
            if last_cp and last_cp["checkpoint_json"]:
                try:
                    prev_cp_hash = json.loads(last_cp["checkpoint_json"]).get("checkpoint_hash")
                except Exception:
                    pass

            checkpoint_data = create_signed_checkpoint(
                blocks=blocks,
                private_key_pem=private_key_pem,
                public_key_pem=public_key_pem,
                sequence=seq,
                prev_checkpoint_hash=prev_cp_hash
            )

            cursor.execute("""
                INSERT INTO checkpoints (
                    sequence, last_block_index, total_blocks, last_block_hash,
                    checkpoint_hash, prev_checkpoint_hash, root_key_fingerprint, signature,
                    created_at, created_by, checkpoint_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                checkpoint_data["sequence"],
                checkpoint_data["last_block_index"],
                checkpoint_data["total_blocks"],
                checkpoint_data["last_block_hash"],
                checkpoint_data.get("checkpoint_hash"),
                checkpoint_data.get("prev_checkpoint_hash"),
                checkpoint_data["root_key_fingerprint"],
                checkpoint_data["signature"],
                checkpoint_data["timestamp"],
                created_by,
                json.dumps(checkpoint_data, ensure_ascii=False)
            ))

        return checkpoint_data

    def get_all_checkpoints(self) -> list[dict[str, Any]]:
        """Retrieve all issued checkpoints ordered by sequence."""
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.*, u.username as creator_username, u.full_name as creator_name
                FROM checkpoints c
                LEFT JOIN users u ON c.created_by = u.id
                ORDER BY c.sequence DESC;
            """)
            return [dict(r) for r in cursor.fetchall()]

    def get_latest_checkpoint(self) -> dict[str, Any] | None:
        """Fetch the latest signed checkpoint recorded in the system."""
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM checkpoints ORDER BY sequence DESC LIMIT 1;")
            row = cursor.fetchone()
            if not row:
                return None
            return json.loads(row["checkpoint_json"])

    def verify_with_checkpoint(
        self,
        checkpoint_data: dict[str, Any],
        public_key_pem: bytes
    ) -> dict[str, Any]:
        """Verify the current database hash-chain against an independently supplied checkpoint."""
        blocks = self.get_all_audit_blocks()
        return verify_ledger_against_checkpoint(blocks, checkpoint_data, public_key_pem)

    def simulate_full_chain_rewrite(
        self,
        tamper_block_index: int = 1,
        tampered_action: str = "TAMPERED_ACTION_REWRITE"
    ) -> bool:
        """
        Simulate an advanced insider attack: modify a block AND recompute the hash
        for every subsequent block in the chain up to the head.
        This produces a chain that is INTERNALLY valid, but will FAIL when verified
        against an external signed checkpoint!
        """
        blocks = self.get_all_audit_blocks()
        if not blocks or tamper_block_index >= len(blocks):
            return False

        # Save snapshot of all affected blocks
        for b in blocks[tamper_block_index:]:
            idx = b["block_index"]
            if idx not in self._tamper_snapshots:
                self._tamper_snapshots[idx] = b.copy()

        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            # 1. Modify the target block
            target = blocks[tamper_block_index]
            target["action"] = tampered_action
            # Recompute target block's hash
            new_target_hash = calculate_block_hash(
                block_index=target["block_index"],
                prev_block_hash=target["prev_block_hash"],
                timestamp=target["timestamp"],
                action=tampered_action,
                doc_uuid=target["doc_uuid"],
                payload_hash=target["payload_hash"]
            )
            target["block_hash"] = new_target_hash
            cursor.execute(
                "UPDATE audit_blocks SET action = ?, block_hash = ? WHERE block_index = ?;",
                (tampered_action, new_target_hash, tamper_block_index)
            )

            # 2. Recalculate and update all subsequent blocks
            prev_hash = new_target_hash
            for i in range(tamper_block_index + 1, len(blocks)):
                b = blocks[i]
                b["prev_block_hash"] = prev_hash
                b_hash = calculate_block_hash(
                    block_index=b["block_index"],
                    prev_block_hash=prev_hash,
                    timestamp=b["timestamp"],
                    action=b["action"],
                    doc_uuid=b["doc_uuid"],
                    payload_hash=b["payload_hash"]
                )
                b["block_hash"] = b_hash
                prev_hash = b_hash
                cursor.execute(
                    "UPDATE audit_blocks SET prev_block_hash = ?, block_hash = ? WHERE block_index = ?;",
                    (b["prev_block_hash"], b_hash, b["block_index"])
                )

        return True
