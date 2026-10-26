"""Document Ingestion, Sanitization, Canonical Digital Signing, Issuance, and Revocation."""
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from ..config import UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH
from ..crypto.hashing import calculate_bytes_hash
from ..crypto.keys import KeyManager
from ..crypto.signature import build_canonical_payload, sign_canonical_payload
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
        2. Compute SHA-256 hash over raw bytes.
        3. Fetch issuer name and bind metadata into a canonical signed payload.
        4. Sign canonical payload digest with RSA-2048 private key.
        5. Store file safely in storage vault (with automatic cleanup on error).
        6. Insert document record and append block to audit ledger hash chain.
        """
        if len(file_bytes) == 0:
            raise ValueError("Tệp tải lên không được rỗng (0 bytes)")
        if len(file_bytes) > MAX_CONTENT_LENGTH:
            raise ValueError(f"Dung lượng tệp vượt quá giới hạn cho phép ({MAX_CONTENT_LENGTH // (1024*1024)}MB)")

        clean_filename = sanitize_filename(original_filename)
        doc_uuid = str(uuid.uuid4())
        file_size = len(file_bytes)
        now_str = datetime.now(timezone.utc).isoformat()
        clean_title = title.strip()
        clean_recipient = recipient_name.strip()
        clean_doc_type = doc_type.strip()

        # 1. Look up issuer identity
        issuer_name = "Cơ quan phát hành"
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT full_name FROM users WHERE id = ?;", (issuer_id,))
            row = cursor.fetchone()
            if row and row["full_name"]:
                issuer_name = row["full_name"]

        # 2. Compute SHA-256 digest of raw file bytes
        doc_hash = calculate_bytes_hash(file_bytes)

        # 3. Construct Canonical Metadata-Bound Payload
        canonical_payload = build_canonical_payload(
            doc_uuid=doc_uuid,
            doc_hash=doc_hash,
            recipient_name=clean_recipient,
            doc_type=clean_doc_type,
            issuer_name=issuer_name,
            issued_at=now_str,
            version=1
        )

        # 4. Digitally Sign the Canonical Payload Digest with Issuer's Private Key
        private_key = self.key_manager.get_private_key()
        signature_hex = sign_canonical_payload(private_key, canonical_payload)

        # 5. Store file safely in storage vault with atomic transaction handling
        storage_filename = f"{doc_uuid}.bin"
        storage_path = UPLOAD_DIR / storage_filename

        try:
            with open(storage_path, "wb") as f:
                f.write(file_bytes)

            with self.db.connection_context() as conn:
                cursor = conn.cursor()

                # Insert Document Record
                cursor.execute("""
                    INSERT INTO documents (
                        doc_uuid, issuer_id, title, recipient_name, doc_type,
                        original_filename, file_size, doc_hash, signature, status,
                        issued_at, file_storage_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?);
                """, (
                    doc_uuid, issuer_id, clean_title, clean_recipient, clean_doc_type,
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
        except Exception:
            # Clean up orphaned physical file if database transaction fails
            if storage_path.exists():
                storage_path.unlink(missing_ok=True)
            raise

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

        with self.db.connection_context() as conn:
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

        return self.get_document_by_uuid(doc_uuid)

    def get_document_by_uuid(self, doc_uuid: str) -> dict[str, Any] | None:
        """Fetch document details along with issuer information."""
        with self.db.connection_context() as conn:
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
        with self.db.connection_context() as conn:
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
        with self.db.connection_context() as conn:
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

    def emergency_batch_revoke(self, issuer_id: int, reason: str, revoked_by: int) -> list[str]:
        """
        Emergency Incident Response:
        When an issuer account is compromised, batch-revoke all active documents issued by this account
        and cryptographically seal each revocation into the immutable audit hash-chain.
        Returns the list of revoked document UUIDs.
        """
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT doc_uuid FROM documents WHERE issuer_id = ? AND status = 'ACTIVE';",
                (issuer_id,)
            )
            rows = cursor.fetchall()
            target_uuids = [r["doc_uuid"] for r in rows]

        revoked_uuids = []
        for doc_uuid in target_uuids:
            self.revoke_document(
                doc_uuid=doc_uuid,
                reason=f"[SỰ CỐ AN NINH / TÀI KHOẢN BỊ XÂM PHẠM] {reason}",
                revoked_by=revoked_by
            )
            revoked_uuids.append(doc_uuid)
        return revoked_uuids


