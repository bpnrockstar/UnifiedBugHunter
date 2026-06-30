"""SAFE variant of path_traversal.py — resolved path confined to BASE_DIR.

Negative case: the eval expects ZERO findings for this file.
"""
import os

from flask import request

BASE_DIR = "/var/www/uploads"


def read_file():
    name = request.args.get("name", "")
    # SAFE: only the basename is used and the real path must stay under BASE_DIR.
    path = os.path.realpath(os.path.join(BASE_DIR, os.path.basename(name)))
    if not path.startswith(BASE_DIR + os.sep):
        raise ValueError("path outside base directory")
    with open(path) as fh:
        return fh.read()
