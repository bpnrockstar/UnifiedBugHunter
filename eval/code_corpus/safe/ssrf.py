"""SAFE variant of ssrf.py — fetch restricted to a host allowlist.

Negative case: the eval expects ZERO findings for this file.
"""
from urllib.parse import urlparse
from urllib.request import urlopen

from flask import request

ALLOWED_HOSTS = {"api.internal.example.com"}


def fetch():
    target = request.args.get("url", "")
    host = urlparse(target).hostname
    # SAFE: only pre-approved hosts are reachable; everything else is rejected.
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return urlopen("https://" + host + "/status").read()
