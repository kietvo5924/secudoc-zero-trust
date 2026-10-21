"""RSA Key Pair Management and Local Keystore."""
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ..config import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, RSA_KEY_SIZE


class KeyManager:
    """Manages the lifecycle, safe derivation, and storage of RSA Cryptographic Keys."""

    def __init__(self, private_path: Path = PRIVATE_KEY_PATH, public_path: Path = PUBLIC_KEY_PATH, key_size: int = RSA_KEY_SIZE):
        self.private_path = Path(private_path)
        self.public_path = Path(public_path)
        self.key_size = key_size
        self._private_key = None
        self._public_key = None
        self.ensure_keys_exist()

    def ensure_keys_exist(self) -> None:
        """Verify that keys exist on disk.

        - If both exist: load them.
        - If private key exists but public key is missing: derive public key safely.
        - If public key exists but private key is missing: raise FileNotFoundError to prevent
          silently generating a new keypair that invalidates previously signed documents.
        - If neither exists: generate and persist a new keypair.
        """
        priv_exists = self.private_path.exists()
        pub_exists = self.public_path.exists()

        if priv_exists and pub_exists:
            self.load_keys()
        elif priv_exists and not pub_exists:
            # Safely recover public key from existing private key
            self._load_private_key_only()
            self._public_key = self._private_key.public_key()
            self._save_public_key(self._public_key)
        elif pub_exists and not priv_exists:
            raise FileNotFoundError(
                f"Tệp khóa riêng (Private Key) không tồn tại tại '{self.private_path}', "
                f"nhưng khóa công khai vẫn tồn tại tại '{self.public_path}'. "
                f"Hệ thống từ chối tự động sinh cặp khóa mới vì sẽ làm mất hiệu lực toàn bộ chữ ký cũ!"
            )
        else:
            self.generate_and_save_keypair()

    def _load_private_key_only(self) -> None:
        """Load private key from disk."""
        with open(self.private_path, "rb") as f:
            self._private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

    def _save_public_key(self, public_key: rsa.RSAPublicKey) -> None:
        """Save public key to disk in SubjectPublicKeyInfo PEM format."""
        self.public_path.parent.mkdir(parents=True, exist_ok=True)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.public_path, "wb") as f:
            f.write(public_pem)

    def generate_and_save_keypair(self) -> None:
        """Generate a new RSA keypair and persist both keys to disk in PEM format."""
        self.private_path.parent.mkdir(parents=True, exist_ok=True)
        self.public_path.parent.mkdir(parents=True, exist_ok=True)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize Private Key (PKCS#8 PEM)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(self.private_path, "wb") as f:
            f.write(private_pem)

        # Serialize Public Key (SubjectPublicKeyInfo PEM)
        self._save_public_key(public_key)

        self._private_key = private_key
        self._public_key = public_key

    def load_keys(self) -> None:
        """Load RSA keypair from disk."""
        self._load_private_key_only()
        with open(self.public_path, "rb") as f:
            self._public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def get_private_key(self) -> rsa.RSAPrivateKey:
        """Return the loaded RSA private key object."""
        if not self._private_key:
            self.load_keys()
        return self._private_key

    def get_public_key(self) -> rsa.RSAPublicKey:
        """Return the loaded RSA public key object."""
        if not self._public_key:
            self.load_keys()
        return self._public_key

    def get_public_key_pem(self) -> str:
        """Return the public key serialized as a UTF-8 PEM string."""
        pub_bytes = self.get_public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes.decode("utf-8")

    def get_public_key_fingerprint(self) -> str:
        """Compute the SHA-256 fingerprint of the SubjectPublicKeyInfo DER encoding.

        Returns formatted fingerprint string: 'SHA256:XX:XX:...' for local root trust verification.
        """
        der_bytes = self.get_public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        raw_hash = hashlib.sha256(der_bytes).hexdigest().upper()
        formatted = ":".join(raw_hash[i:i + 2] for i in range(0, len(raw_hash), 2))
        return f"SHA256:{formatted}"

