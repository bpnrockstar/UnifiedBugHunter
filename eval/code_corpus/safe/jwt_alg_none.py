"""SAFE variant of jwt_alg_none.py — signature enforced, fixed algorithm.

Negative case: the eval expects ZERO findings for this file.
"""
import jwt

SECRET = "loaded-from-secret-manager-at-runtime"  # noqa: S105 (placeholder, not a real secret)


def verify(token: str):
    # SAFE: signature verified and the algorithm is pinned to HS256.
    return jwt.decode(token, SECRET, algorithms=["HS256"])
