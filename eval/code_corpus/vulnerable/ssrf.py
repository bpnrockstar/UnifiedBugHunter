# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""SSRF — server fetches a user-controlled URL with no allowlist.

Ground-truth finding: vuln_class=ssrf on the urlopen line below.
"""
from urllib.request import urlopen

from flask import request


def fetch():
    target = request.args.get("url", "")
    # VULN: open-ended fetch of attacker-controlled URL — SSRF sink.
    return urlopen(target).read()
