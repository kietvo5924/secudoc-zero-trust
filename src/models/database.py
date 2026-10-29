"""SQLite Database Management, Schema Initialization, and Seeding."""
import sqlite3
import hashlib
import secrets
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from ..config import DATABASE_PATH, PASSWORD_HASH_ITERATIONS, PASSWORD_SALT_BYTES, DEMO_MODE
from ..crypto.merkle import GENESIS_PREV_HASH, calculate_block_hash


def _hash_seed_password(password: str) -> tuple[str, str]:
    """Helper to hash seed passwords with PBKDF2-HMAC-SHA256."""
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS
    )
    return dk.hex(), salt.hex()


class DatabaseManager:
    """Manages SQLite connection, schema lifecycle, and database queries."""

    def __init__(self, db_path: str | Path = DATABASE_PATH, seed_demo: bool | None = None):
        self.db_path = str(db_path)
        self.seed_demo = seed_demo if seed_demo is not None else DEMO_MODE
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextmanager
    def connection_context(self):
        """Context manager that automatically commits transactions and cleanly closes connections."""
        conn = self.get_connection()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize all database tables and indexes if they do not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection_context() as conn:
            cursor = conn.cursor()

            # 1. Users Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL, -- 'ISSUER', 'AUDITOR', 'PUBLIC_VERIFIER'
                    status TEXT NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'LOCKED', 'COMPROMISED'
                    created_at TEXT NOT NULL
                );
            """)

            # Ensure status column exists in users table for existing databases
            cursor.execute("PRAGMA table_info(users);")
            user_cols = [row["name"] for row in cursor.fetchall()]
            if "status" not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';")

            # 2. Documents Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    doc_uuid TEXT UNIQUE NOT NULL,
                    issuer_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    recipient_name TEXT NOT NULL,
                    doc_type TEXT NOT NULL, -- 'DIPLOMA', 'TRANSCRIPT', 'CERTIFICATE', 'OFFICIAL_LETTER'
                    original_filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    doc_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'REVOKED'
                    issued_at TEXT NOT NULL,
                    file_storage_path TEXT NOT NULL,
                    FOREIGN KEY (issuer_id) REFERENCES users(id)
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_doc_hash ON documents(doc_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_doc_uuid ON documents(doc_uuid);")

            # 3. Audit Blocks Table (Tamper-Evident Hash Chain)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_blocks (
                    block_index INTEGER PRIMARY KEY,
                    prev_block_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL, -- 'GENESIS', 'ISSUE', 'REVOKE'
                    doc_uuid TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_block_hash ON audit_blocks(block_hash);")

            # 4. Revocations Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS revocations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    doc_uuid TEXT NOT NULL,
                    revoked_by INTEGER NOT NULL,
                    revocation_reason TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    FOREIGN KEY (doc_uuid) REFERENCES documents(doc_uuid),
                    FOREIGN KEY (revoked_by) REFERENCES users(id)
                );
            """)

        # Seed initial data
        self.seed_default_users()
        self.ensure_genesis_block()

    def seed_default_users(self, force: bool = False) -> bool:
        """Seed default demo accounts only in DEMO_MODE or when explicitly forced.

        In production mode (DEMO_MODE=False), no demo accounts are created.
        """
        if not self.seed_demo and not force:
            logging.info("ℹ️  [PRODUCTION] Skipping demo account seeding (seed_demo=False).")
            return False

        with self.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM users;")
            if cursor.fetchone()["count"] == 0:
                now_str = datetime.now(timezone.utc).isoformat()
                users_to_seed = [
                    ("issuer", "IssuerSecurePass2026!", "Phòng Đào Tạo & Khảo Thí Đại Học", "ISSUER"),
                    ("auditor", "AuditorPass2026!", "Kiểm Toán Viên An Ninh Hệ Thống", "AUDITOR"),
                    ("verifier", "VerifierPass2026!", "Nhà Tuyển Dụng / Thẩm Định Viên", "PUBLIC_VERIFIER"),
                ]
                for uname, pwd, fname, role in users_to_seed:
                    pwd_hash, salt = _hash_seed_password(pwd)
                    cursor.execute("""
                        INSERT INTO users (username, password_hash, salt, full_name, role, created_at)
                        VALUES (?, ?, ?, ?, ?, ?);
                    """, (uname, pwd_hash, salt, fname, role, now_str))
                logging.info("ℹ️  [DEMO_MODE] Seeded demo accounts: issuer, auditor, verifier")
                return True
        return False

    def ensure_genesis_block(self) -> None:
        """Create the cryptographic Genesis Block if audit_blocks is empty."""
        with self.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM audit_blocks;")
            if cursor.fetchone()["count"] == 0:
                now_str = datetime.now(timezone.utc).isoformat()
                genesis_payload = hashlib.sha256(b"SECUDOC_GENESIS_ROOT_OF_TRUST_2026").hexdigest()
                block_hash = calculate_block_hash(
                    block_index=0,
                    prev_block_hash=GENESIS_PREV_HASH,
                    timestamp=now_str,
                    action="GENESIS",
                    doc_uuid="00000000-0000-0000-0000-000000000000",
                    payload_hash=genesis_payload
                )
                cursor.execute("""
                    INSERT INTO audit_blocks (block_index, prev_block_hash, timestamp, action, doc_uuid, payload_hash, block_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """, (0, GENESIS_PREV_HASH, now_str, "GENESIS", "00000000-0000-0000-0000-000000000000", genesis_payload, block_hash))


_db_manager = None

def get_db(db_path: str | Path = DATABASE_PATH) -> DatabaseManager:
    """Singleton getter for DatabaseManager."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path)
    return _db_manager

