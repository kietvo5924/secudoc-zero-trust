"""Document Ingestion, Sanitization, Digital Signing, Issuance, and Revocation."""
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Any
from ..config import UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH
from ..crypto.hashing import calculate_bytes_hash
from ..crypto.keys import KeyManager
from ..crypto.signature import sign_hash
from ..crypto.merkle import calculate_block_hash
from ..models.database import DatabaseManager, get_db


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename against Path Traversal and illegal characters.
    Strips directory separators and extracts only the base filename.
    """
    cleaned = Path(filename).name
    # Keep only alphanumeric, dots, underscores, dashes
    cleaned = re.sub(r"[^\w\.-]", "_", cleaned)
    return cleaned if cleaned else f"document_{uuid.uuid4().hex[:8]}"


class DocumentService:
    """Core service for managing document lifecycle, cryptographic sealing, and revocation."""

    def __init__(self, db_manager: DatabaseManager | None = None, key_manager: KeyManager | None = None):
        self.db = db_manager or get_db()
        self.key_manager = key_manager or KeyManager()

    def issue_document(
        self,
        issuer_id: int,
        title: str,
        recipient_name: str,
        doc_type: str,
        file_bytes: bytes,
        original_filename: str
    ) -> dict[str, Any]:
        """
        Issue and cryptographically seal a document:
        1. Sanitize filename and validate file size.
        2. Compute SHA-256 hash.
        3. Sign hash with RSA-2048 private key.
        4. Store isolated file in vault.
        5. Insert document record.
        6. Append block to audit ledger hash chain.
        """
        if len(file_bytes) == 0:
            raise ValueError("Tệp tải lên không được rỗng (0 bytes)")
        if len(file_bytes) > MAX_CONTENT_LENGTH:
            raise ValueError(f"Dung lượng tệp vượt quá giới hạn cho phép ({MAX_CONTENT_LENGTH // (1024*1024)}MB)")

        clean_filename = sanitize_filename(original_filename)
        doc_uuid = str(uuid.uuid4())
        file_size = len(file_bytes)
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Compute SHA-256 digest
        doc_hash = calculate_bytes_hash(file_bytes)

        # 2. Digitally Sign the Hash with Issuer's Private Key
        private_key = self.key_manager.get_private_key()
        signature_hex = sign_hash(private_key, doc_hash)

        # 3. Store file safely in storage vault with isolated UUID name
        storage_filename = f"{doc_uuid}.bin"
        storage_path = UPLOAD_DIR / storage_filename
        with open(storage_path, "wb") as f:
            f.write(file_bytes)

        # 4. Database operations: Insert document and append to audit ledger
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Insert Document Record
            cursor.execute("""
                INSERT INTO documents (
                    doc_uuid, issuer_id, title, recipient_name, doc_type,
                    original_filename, file_size, doc_hash, signature, status,
                    issued_at, file_storage_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?);
            """, (
                doc_uuid, issuer_id, title.strip(), recipient_name.strip(), doc_type.strip(),
                clean_filename, file_size, doc_hash, signature_hex, now_str, str(storage_path)
            ))

            # Fetch last audit block to link hash chain
            cursor.execute("SELECT block_index, block_hash FROM audit_blocks ORDER BY block_index DESC LIMIT 1;")
            last_block = cursor.fetchone()
            new_block_index = last_block["block_index"] + 1 if last_block else 0
            prev_block_hash = last_block["block_hash"] if last_block else "0" * 64

            new_block_hash = calculate_block_hash(
                block_index=new_block_index,
                prev_block_hash=prev_block_hash,
                timestamp=now_str,
                action="ISSUE",
                doc_uuid=doc_uuid,
                payload_hash=doc_hash
            )

            cursor.execute("""
                INSERT INTO audit_blocks (
                    block_index, prev_block_hash, timestamp, action, doc_uuid, payload_hash, block_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (
                new_block_index, prev_block_hash, now_str, "ISSUE", doc_uuid, doc_hash, new_block_hash
            ))

            conn.commit()

        return self.get_document_by_uuid(doc_uuid)

    def revoke_document(self, doc_uuid: str, revoked_by: int, reason: str) -> dict[str, Any]:
        """
        Revoke an active document:
        1. Set status = 'REVOKED'.
        2. Insert record in revocations table.
        3. Append a REVOKE block to the audit hash chain.
        """
        doc = self.get_document_by_uuid(doc_uuid)
        if not doc:
            raise ValueError(f"Không tìm thấy tài liệu có UUID: {doc_uuid}")
        if doc["status"] == "REVOKED":
            raise ValueError("Tài liệu này đã bị thu hồi trước đó")

        now_str = datetime.now(timezone.utc).isoformat()
        reason_clean = reason.strip() or "Thu hồi theo quyết định của cơ quan phát hành"

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Update document status
            cursor.execute("UPDATE documents SET status = 'REVOKED' WHERE doc_uuid = ?;", (doc_uuid,))

            # Log revocation reason
            cursor.execute("""
                INSERT INTO revocations (doc_uuid, revoked_by, revocation_reason, revoked_at)
                VALUES (?, ?, ?, ?);
            """, (doc_uuid, revoked_by, reason_clean, now_str))

            # Fetch last block to append to hash chain
            cursor.execute("SELECT block_index, block_hash FROM audit_blocks ORDER BY block_index DESC LIMIT 1;")
            last_block = cursor.fetchone()
            new_block_index = last_block["block_index"] + 1
            prev_block_hash = last_block["block_hash"]

            revoke_payload_hash = calculate_bytes_hash(f"REVOCATION:{doc_uuid}:{reason_clean}".encode("utf-8"))
            new_block_hash = calculate_block_hash(
                block_index=new_block_index,
                prev_block_hash=prev_block_hash,
                timestamp=now_str,
                action="REVOKE",
                doc_uuid=doc_uuid,
                payload_hash=revoke_payload_hash
            )

            cursor.execute("""
                INSERT INTO audit_blocks (
                    block_index, prev_block_hash, timestamp, action, doc_uuid, payload_hash, block_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (
                new_block_index, prev_block_hash, now_str, "REVOKE", doc_uuid, revoke_payload_hash, new_block_hash
            ))

            conn.commit()

        return self.get_document_by_uuid(doc_uuid)

    def get_document_by_uuid(self, doc_uuid: str) -> dict[str, Any] | None:
        """Fetch document details along with issuer information."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.*, u.full_name as issuer_name, u.username as issuer_username,
                       r.revocation_reason, r.revoked_at
                FROM documents d
                JOIN users u ON d.issuer_id = u.id
                LEFT JOIN revocations r ON d.doc_uuid = r.doc_uuid
                WHERE d.doc_uuid = ?;
            """, (doc_uuid,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_document_by_hash(self, doc_hash: str) -> dict[str, Any] | None:
        """Fetch document details matching a specific SHA-256 hash."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.*, u.full_name as issuer_name, u.username as issuer_username,
                       r.revocation_reason, r.revoked_at
                FROM documents d
                JOIN users u ON d.issuer_id = u.id
                LEFT JOIN revocations r ON d.doc_uuid = r.doc_uuid
                WHERE d.doc_hash = ?;
            """, (doc_hash.lower().strip(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_documents(self, issuer_id: int | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """List documents, optionally filtered by issuer."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            if issuer_id is not None:
                cursor.execute("""
                    SELECT d.*, u.full_name as issuer_name
                    FROM documents d
                    JOIN users u ON d.issuer_id = u.id
                    WHERE d.issuer_id = ?
                    ORDER BY d.id DESC LIMIT ?;
                """, (issuer_id, limit))
            else:
                cursor.execute("""
                    SELECT d.*, u.full_name as issuer_name
                    FROM documents d
                    JOIN users u ON d.issuer_id = u.id
                    ORDER BY d.id DESC LIMIT ?;
                """, (limit,))
            return [dict(r) for r in cursor.fetchall()]
