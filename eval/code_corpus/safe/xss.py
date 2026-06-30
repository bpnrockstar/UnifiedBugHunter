"""SAFE variant of xss.py — output is HTML-escaped before reflection.

Negative case: the eval expects ZERO findings for this file.
"""
from html import escape

from flask import request


def greet():
    name = request.args.get("name", "")
    # SAFE: escape() neutralizes <, >, & before it reaches the page.
    return "<h1>Hello " + escape(name) + "</h1>"
