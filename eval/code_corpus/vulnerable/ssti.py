# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""Server-Side Template Injection — user input compiled as a Jinja2 template.

Ground-truth finding: vuln_class=ssti on the render_template_string line below.
"""
from flask import request
from jinja2 import Template


def render():
    tmpl = request.args.get("tmpl", "")
    # VULN: user input becomes the template source — SSTI → RCE via sandbox escape.
    return Template("Hello " + tmpl).render()
