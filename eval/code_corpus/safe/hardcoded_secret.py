"""SAFE variant of hardcoded_secret.py — secret read from the environment.

Negative case: the eval expects ZERO findings for this file.
"""
import os


def client_config() -> dict:
    # SAFE: credential injected at runtime; nothing sensitive in source.
    return {"aws_secret_access_key": os.environ["AWS_SECRET_ACCESS_KEY"]}
