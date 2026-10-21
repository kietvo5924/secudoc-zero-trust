"""Authentication, Password Security (PBKDF2), and Role-Based Access Control (RBAC)."""
import time
import hashlib
import secrets
from functools import wraps
from flask import session, redirect, url_for, abort, request, jsonify
from ..config import (
    PASSWORD_HASH_ITERATIONS,
    PASSWORD_SALT_BYTES,
    LOGIN_MAX_FAILED_ATTEMPTS,
    LOGIN_LOCKOUT_SECONDS,
)
from ..models.database import DatabaseManager, get_db

# In-memory store for rate limiting failed login attempts: {identifier: [timestamps]}
_failed_login_attempts: dict[str, list[float]] = {}


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
    """Handles user authentication, session binding, rate limiting, and credential validation."""

    def __init__(self, db_manager: DatabaseManager | None = None):
        self.db = db_manager or get_db()

    @staticmethod
    def check_rate_limit(identifier: str) -> tuple[bool, int]:
        """
        Check whether an IP or username has exceeded the allowed failed login threshold.
        Returns: (is_allowed, seconds_remaining)
        """
        now = time.time()
        attempts = _failed_login_attempts.get(identifier, [])
        # Retain attempts within the sliding lockout window
        recent_attempts = [t for t in attempts if now - t < LOGIN_LOCKOUT_SECONDS]
        _failed_login_attempts[identifier] = recent_attempts

        if len(recent_attempts) >= LOGIN_MAX_FAILED_ATTEMPTS:
            oldest_relevant = recent_attempts[0]
            remaining = int(LOGIN_LOCKOUT_SECONDS - (now - oldest_relevant))
            return False, max(1, remaining)
        return True, 0

    @staticmethod
    def record_failure(identifier: str) -> None:
        """Record a failed login attempt for the identifier."""
        now = time.time()
        if identifier not in _failed_login_attempts:
            _failed_login_attempts[identifier] = []
        _failed_login_attempts[identifier].append(now)

    @staticmethod
    def reset_failures(identifier: str) -> None:
        """Reset failed attempt counters upon successful authentication."""
        _failed_login_attempts.pop(identifier, None)

    def authenticate(self, username: str, password: str, client_ip: str = "") -> dict | None:
        """
        Authenticate user by username and password with rate-limiting backoff.
        Raises ValueError if rate limited. Returns user dict or None.
        """
        ident = client_ip.strip() or username.strip().lower()

        is_allowed, wait_sec = self.check_rate_limit(ident)
        if not is_allowed:
            raise PermissionError(f"Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau {wait_sec} giây.")

        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?;", (username.strip(),))
            user = cursor.fetchone()
            if not user:
                self.record_failure(ident)
                return None

            if verify_password(password, user["password_hash"], user["salt"]):
                self.reset_failures(ident)
                return {
                    "id": user["id"],
                    "username": user["username"],
                    "full_name": user["full_name"],
                    "role": user["role"],
                    "created_at": user["created_at"]
                }

            self.record_failure(ident)
            return None

    def get_user_by_id(self, user_id: int) -> dict | None:
        """Fetch user by primary key ID."""
        with self.db.connection_context() as conn:
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

