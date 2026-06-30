"""SAFE variant of weak_crypto.py — PBKDF2-HMAC-SHA256 with a salt.

Negative case: the eval expects ZERO findings for this file.
"""
import hashlib
import os


def hash_password(password: str) -> bytes:
    # SAFE: salted, key-stretched KDF designed for passwords.
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
