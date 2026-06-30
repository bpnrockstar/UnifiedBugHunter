# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""Path traversal — user input joined to a base dir with no containment check.

Ground-truth finding: vuln_class=path-traversal on the open line below.
"""
import os

from flask import request

BASE_DIR = "/var/www/uploads"


def read_file():
    name = request.args.get("name", "")
    # VULN: '../../etc/passwd' escapes BASE_DIR — path traversal sink.
    path = os.path.join(BASE_DIR, name)
    with open(path) as fh:
        return fh.read()
