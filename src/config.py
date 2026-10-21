"""Application Configuration for SecuDoc System.

Enforces secure defaults, environment variable loading, role-based parameters,
and explicit separation between DEMO_MODE and PRODUCTION.
"""
import os
import sys
import logging
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
KEY_DIR = DATA_DIR / "keys"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
KEY_DIR.mkdir(parents=True, exist_ok=True)


def _load_env_file(env_path: Path) -> None:
    """Deterministically parse and load environment variables from .env file."""
    if not env_path.is_file():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, val = stripped.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                # Do not overwrite already existing environment variables
                if key not in os.environ:
                    os.environ[key] = val


# Load .env file from project root if present
_load_env_file(BASE_DIR / ".env")

# Operating Mode: DEMO_MODE vs PRODUCTION
# DEMO_MODE defaults to True for university classroom labs / demonstrations,
# but disables dangerous endpoints and enforces strict secrets in production mode.
DEMO_MODE = os.environ.get("DEMO_MODE", "1").strip().lower() in ("1", "true", "yes")

# Database Configuration
DATABASE_PATH = os.environ.get("DATABASE_PATH", str(DATA_DIR / "secudoc.db"))
ATTACK_SANDBOX_DB = os.environ.get("ATTACK_SANDBOX_DB", str(DATA_DIR / "attack_sandbox.db"))

# Secret Key Handling:
# - In Production (DEMO_MODE=False): SECRET_KEY is strictly required from environment.
# - In Demo Mode (DEMO_MODE=True): A fallback demo key is permitted with a prominent warning.
_INSECURE_DEMO_KEY = "secudoc-local-demo-secret-key-2026-unsecure"
_raw_secret = os.environ.get("SECRET_KEY", "").strip()

if not _raw_secret:
    if DEMO_MODE:
        SECRET_KEY = _INSECURE_DEMO_KEY
        logging.warning("⚠️  [SECURITY WARNING] Using default fallback SECRET_KEY in DEMO_MODE. Configure SECRET_KEY in .env for security.")
    else:
        raise RuntimeError(
            "CRITICAL CONFIGURATION ERROR: SECRET_KEY environment variable is missing in production mode! "
            "Set a cryptographically strong SECRET_KEY before deploying."
        )
else:
    if not DEMO_MODE and _raw_secret in (_INSECURE_DEMO_KEY, "secudoc-insecure-dev-key-change-in-prod-2026", "change-this-to-a-secure-random-32-byte-hex-in-production"):
        raise RuntimeError("CRITICAL CONFIGURATION ERROR: Insecure/default SECRET_KEY detected in production mode!")
    SECRET_KEY = _raw_secret

# Cryptography Parameters
RSA_KEY_SIZE = int(os.environ.get("RSA_KEY_SIZE", "2048"))
PASSWORD_HASH_ITERATIONS = int(os.environ.get("PASSWORD_HASH_ITERATIONS", "100000"))
PASSWORD_SALT_BYTES = 16

# File Upload Policies
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH_BYTES", str(10 * 1024 * 1024)))  # 10 MB limit
ALLOWED_EXTENSIONS = {"pdf", "docx", "png", "jpg", "jpeg", "txt"}
CHUNK_SIZE_BYTES = 64 * 1024  # 64 KB per stream chunk

# Key File Locations
PRIVATE_KEY_PATH = KEY_DIR / "root_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "root_public.pem"

# Web Server & Session Security Settings
SERVER_HOST = os.environ.get("HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("PORT", "5000"))

# DEBUG defaults to False; only enabled if explicitly requested in DEMO_MODE
DEBUG = (
    os.environ.get("FLASK_ENV", "").lower() == "development"
    or os.environ.get("FLASK_DEBUG", "0").strip() in ("1", "true")
) and DEMO_MODE

# Session Cookie Hardening
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("USE_HTTPS", "0").strip().lower() in ("1", "true", "yes")

# Rate Limiting Parameters
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))
LOGIN_MAX_FAILED_ATTEMPTS = int(os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))

