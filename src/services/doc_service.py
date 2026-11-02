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


def mask_recipient_name(name: str) -> str:
    """Mask PII recipient names for public and unauthenticated display."""
    parts = name.strip().split()
    if not parts:
        return "***"
    if len(parts) == 1:
        return parts[0][:1] + "***"
    return " ".join(p[:1] + "***" for p in parts)



class IncidentRevokeResult(list):
    """
    Structured incident response result that acts as a list of revoked UUIDs
    for backward compatibility with older tests/callers, while supporting dict-style
    metadata access for auditing and API endpoints.
    """
    def __init__(self, revoked_uuids: list[str], **kwargs):
        super().__init__(revoked_uuids)
        self.status = kwargs.get("status", "INCIDENT_RESOLVED")
        self.issuer_id = kwargs.get("issuer_id")
        self.issuer_username = kwargs.get("issuer_username")
        self.account_status = kwargs.get("account_status", "COMPROMISED")
        self.revoked_count = len(revoked_uuids)
        self.revoked_uuids = revoked_uuids
        self.failed_count = kwargs.get("failed_count", 0)
        self.failed_uuids = kwargs.get("failed_uuids", [])
        self._meta = {
            "status": self.status,
            "issuer_id": self.issuer_id,
            "issuer_username": self.issuer_username,
            "account_status": self.account_status,
            "revoked_count": self.revoked_count,
            "revoked_uuids": self.revoked_uuids,
            "failed_count": self.failed_count,
            "failed_uuids": self.failed_uuids
        }

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._meta[key]
        return super().__getitem__(key)

    def get(self, key, default=None):
        return self._meta.get(key, default)

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

        # Validate file extension against allowed whitelist
        ext = Path(original_filename).suffix.lstrip(".").lower()
        if not ext or ext not in ALLOWED_EXTENSIONS:
            allowed_str = ", ".join(sorted(ALLOWED_EXTENSIONS))
            raise ValueError(
                f"Phần mở rộng tệp '.{ext}' không hợp lệ hoặc không được hỗ trợ! "
                f"Hệ thống chỉ chấp nhận: {allowed_str}"
            )

        clean_filename = sanitize_filename(original_filename)
        doc_uuid = str(uuid.uuid4())
        file_size = len(file_bytes)
        now_str = datetime.now(timezone.utc).isoformat()
        clean_title = title.strip()
        clean_recipient = recipient_name.strip()
        clean_doc_type = doc_type.strip()

        # 1. Look up issuer identity and verify account status
        issuer_name = "Cơ quan phát hành"
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT full_name, status FROM users WHERE id = ?;", (issuer_id,))
            row = cursor.fetchone()
            if row:
                row_dict = dict(row)
                if row_dict.get("status") and row_dict["status"] != "ACTIVE":
                    raise PermissionError(
                        f"Tài khoản Issuer '{row_dict.get('full_name')}' đang ở trạng thái '{row_dict['status']}' và đã bị khóa, "
                        f"không thể phát hành văn bản mới."
                    )
                if row_dict.get("full_name"):
                    issuer_name = row_dict["full_name"]

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
            title=clean_title,
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
        1. Verify caller authorization: ISSUER can only revoke their own documents.
        2. Set status = 'REVOKED'.
        3. Insert record in revocations table.
        4. Append a REVOKE block to the audit hash chain.
        """
        doc = self.get_document_by_uuid(doc_uuid)
        if not doc:
            raise ValueError(f"Không tìm thấy tài liệu có UUID: {doc_uuid}")
        if doc["status"] == "REVOKED":
            raise ValueError("Tài liệu này đã bị thu hồi trước đó")

        # Least Privilege: Verify issuer ownership
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE id = ?;", (revoked_by,))
            u_row = cursor.fetchone()
            if u_row and u_row["role"] == "ISSUER" and doc["issuer_id"] != revoked_by:
                raise PermissionError("Issuer không có quyền thu hồi tài liệu của cơ quan phát hành khác.")

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

    def emergency_batch_revoke(self, issuer_id: int, reason: str, revoked_by: int) -> dict[str, Any]:
        """
        Emergency Incident Response:
        When an issuer account is compromised:
        1. Validate target account existence and strictly verify its role is 'ISSUER'.
           Rejects attempts to compromise AUDITOR or PUBLIC_VERIFIER accounts.
        2. Lock the target account with status = 'COMPROMISED'.
        3. Inventory and atomically batch-revoke all 'ACTIVE' documents issued by this account.
        4. Append cryptographic audit blocks for each revocation into the immutable hash chain.
        5. Return comprehensive structured result ensuring idempotency and failure tracing.
        """
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, full_name, role, status FROM users WHERE id = ?;", (issuer_id,))
            target_user = cursor.fetchone()
            if not target_user:
                raise ValueError(f"Không tìm thấy tài khoản người dùng với ID: {issuer_id}")

            target_dict = dict(target_user)
            if target_dict["role"] != "ISSUER":
                raise ValueError(
                    f"Tài khoản mục tiêu '{target_dict['username']}' có vai trò '{target_dict['role']}'. "
                    f"Quy trình xử lý sự cố Issuer chỉ được phép áp dụng cho tài khoản ISSUER, "
                    f"không được xử lý nhầm tài khoản AUDITOR hoặc PUBLIC_VERIFIER!"
                )

            # Idempotent lock of the issuer account
            cursor.execute("UPDATE users SET status = 'COMPROMISED' WHERE id = ?;", (issuer_id,))

            # Inventory ACTIVE documents
            cursor.execute(
                "SELECT doc_uuid FROM documents WHERE issuer_id = ? AND status = 'ACTIVE';",
                (issuer_id,)
            )
            rows = cursor.fetchall()
            active_uuids = [r["doc_uuid"] for r in rows]

        revoked_uuids: list[str] = []
        failed_uuids: list[dict[str, str]] = []

        now_str = datetime.now(timezone.utc).isoformat()
        reason_clean = f"[SỰ CỐ AN NINH / TÀI KHOẢN BỊ XÂM PHẠM] {reason.strip()}"

        # Revoke documents atomically within a single connection transaction
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            for doc_uuid in active_uuids:
                try:
                    # Update document status
                    cursor.execute("UPDATE documents SET status = 'REVOKED' WHERE doc_uuid = ?;", (doc_uuid,))
                    # Record revocation
                    cursor.execute("""
                        INSERT INTO revocations (doc_uuid, revoked_by, revocation_reason, revoked_at)
                        VALUES (?, ?, ?, ?);
                    """, (doc_uuid, revoked_by, reason_clean, now_str))

                    # Fetch last block
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
                    revoked_uuids.append(doc_uuid)
                except Exception as exc:
                    failed_uuids.append({"doc_uuid": doc_uuid, "error": str(exc)})

        return IncidentRevokeResult(
            revoked_uuids=revoked_uuids,
            status="INCIDENT_RESOLVED" if not failed_uuids else "PARTIALLY_RESOLVED",
            issuer_id=issuer_id,
            issuer_username=target_dict["username"],
            account_status="COMPROMISED",
            failed_count=len(failed_uuids),
            failed_uuids=failed_uuids
        )


