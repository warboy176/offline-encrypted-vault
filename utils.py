import secrets
import hashlib

SALT_LENGTH = 16
PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32


def generate_salt() -> bytes:
    """Generate a random salt for key derivation."""
    return secrets.token_bytes(SALT_LENGTH)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a passphrase and salt using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, KEY_LENGTH)
