# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""Weak cryptography — MD5 used to hash passwords.

Ground-truth finding: vuln_class=weak-crypto on the hashlib.md5 line below.
"""
import hashlib


def hash_password(password: str) -> str:
    # VULN: MD5 is broken/fast — unsuitable for password hashing.
    return hashlib.md5(password.encode()).hexdigest()
