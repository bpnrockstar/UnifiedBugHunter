# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""JWT 'alg:none' — signature verification disabled, accepts forged tokens.

Ground-truth finding: vuln_class=jwt-alg-none on the jwt.decode line below.
"""
import jwt


def verify(token: str):
    # VULN: verify_signature off + 'none' allowed — any forged token is accepted.
    return jwt.decode(
        token,
        options={"verify_signature": False},
        algorithms=["none", "HS256"],
    )
