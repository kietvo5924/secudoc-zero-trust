"""Digital Signature Engine (RSA-PKCS#1 v1.5 with SHA-256)."""
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def sign_hash(private_key: rsa.RSAPrivateKey, hash_hex: str) -> str:
    """
    Sign a SHA-256 hexadecimal hash string using the RSA private key.
    Returns: Signature encoded as a hexadecimal string.
    """
    message_bytes = hash_hex.encode("utf-8")
    signature = private_key.sign(
        message_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()


def verify_signature(public_key: rsa.RSAPublicKey, hash_hex: str, signature_hex: str) -> bool:
    """
    Verify whether a hexadecimal RSA signature matches the given hash string.
    Returns: True if valid; False if forged, corrupted, or signed by another key.
    """
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        message_bytes = hash_hex.encode("utf-8")
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
