"""SAFE variant of insecure_deserialization.py — JSON, not pickle.

Negative case: the eval expects ZERO findings for this file.
"""
import json

from flask import request


def load_session():
    blob = request.get_data()
    # SAFE: JSON is data-only — no code paths reachable from the payload.
    return json.loads(blob)
