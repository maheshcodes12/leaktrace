"""
AES-256-GCM encryption for PDFs.
File format: [4 bytes magic][16 bytes salt][12 bytes nonce][ciphertext+16 byte tag]
"""

import os
import struct
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"LT\x01\x00"  # LeakTrace v1


def _derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=260000)
    return kdf.derive(password)


def encrypt(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return MAGIC + salt + nonce + ciphertext


def decrypt(data: bytes, password: str) -> bytes:
    if data[:4] != MAGIC:
        raise ValueError("Not a LeakTrace encrypted file or wrong version.")
    salt = data[4:20]
    nonce = data[20:32]
    ciphertext = data[32:]
    key = _derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or file is corrupted.")


def load_master_password(key_path: str) -> str:
    """Load or generate master password from key file."""
    if os.path.exists(key_path):
        with open(key_path, "r") as f:
            return f.read().strip()
    # Generate and save
    pw = os.urandom(32).hex()
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    with open(key_path, "w") as f:
        f.write(pw)
    os.chmod(key_path, 0o600)
    return pw
