# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""Reflected XSS — user input echoed into an HTML response without escaping.

Ground-truth finding: vuln_class=xss on the return line below.
"""
from flask import request


def greet():
    name = request.args.get("name", "")
    # VULN: raw f-string into HTML body — reflected XSS sink.
    return "<h1>Hello " + name + "</h1>"
