"""Authentication, Password Security (PBKDF2), and Role-Based Access Control (RBAC)."""
import hashlib
import secrets
from functools import wraps
from flask import session, redirect, url_for, abort, request, jsonify
from ..config import PASSWORD_HASH_ITERATIONS, PASSWORD_SALT_BYTES
from ..models.database import DatabaseManager, get_db


def hash_password(password: str) -> tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a cryptographically secure random salt.
    Returns: (password_hash_hex, salt_hex)
    """
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS
    )
    return dk.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """
    Verify password against stored hash using constant-time comparison to prevent timing attacks.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_HASH_ITERATIONS
        )
        return secrets.compare_digest(dk.hex(), stored_hash)
    except (ValueError, TypeError):
        return False


class AuthService:
    """Handles user authentication, session binding, and credential validation."""

    def __init__(self, db_manager: DatabaseManager | None = None):
        self.db = db_manager or get_db()

    def authenticate(self, username: str, password: str) -> dict | None:
        """Authenticate user by username and password. Returns user dict or None."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?;", (username.strip(),))
            user = cursor.fetchone()
            if not user:
                return None

            if verify_password(password, user["password_hash"], user["salt"]):
                return {
                    "id": user["id"],
                    "username": user["username"],
                    "full_name": user["full_name"],
                    "role": user["role"],
                    "created_at": user["created_at"]
                }
            return None

    def get_user_by_id(self, user_id: int) -> dict | None:
        """Fetch user by primary key ID."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, full_name, role, created_at FROM users WHERE id = ?;", (user_id,))
            user = cursor.fetchone()
            return dict(user) if user else None


def require_role(*allowed_roles: str):
    """
    Decorator to enforce Role-Based Access Control on Flask route endpoints.
    Blocks unauthorized users with HTTP 403 or redirects unauthenticated visitors to login.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get("user")
            if not user:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": "Unauthorized", "message": "Yêu cầu đăng nhập"}), 401
                return redirect(url_for("login", next=request.path))

            user_role = user.get("role")
            if allowed_roles and user_role not in allowed_roles:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Forbidden",
                        "message": f"Vai trò '{user_role}' không có quyền truy cập chức năng này"
                    }), 403
                abort(403)

            return fn(*args, **kwargs)
        return wrapper
    return decorator
