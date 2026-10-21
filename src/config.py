"""Application Configuration for SecuDoc System."""
import os
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

# Database Configuration
DATABASE_PATH = os.environ.get("DATABASE_PATH", str(DATA_DIR / "secudoc.db"))

# Security & Cryptography Parameters
SECRET_KEY = os.environ.get("SECRET_KEY", "secudoc-insecure-dev-key-change-in-prod-2026")
RSA_KEY_SIZE = int(os.environ.get("RSA_KEY_SIZE", "2048"))
PASSWORD_HASH_ITERATIONS = int(os.environ.get("PASSWORD_HASH_ITERATIONS", "100000"))
PASSWORD_SALT_BYTES = 16

# File Upload Policies
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH_BYTES", str(10 * 1024 * 1024))) # 10 MB
ALLOWED_EXTENSIONS = {"pdf", "docx", "png", "jpg", "jpeg", "txt"}
CHUNK_SIZE_BYTES = 64 * 1024 # 64 KB per stream chunk

# Key File Locations
PRIVATE_KEY_PATH = KEY_DIR / "root_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "root_public.pem"

# Web Server Settings
SERVER_HOST = os.environ.get("HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("PORT", "5000"))
DEBUG = os.environ.get("FLASK_ENV", "development") == "development"
