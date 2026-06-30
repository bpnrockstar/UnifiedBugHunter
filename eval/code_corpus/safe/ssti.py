"""SAFE variant of ssti.py — user input is template DATA, not template SOURCE.

Negative case: the eval expects ZERO findings for this file.
"""
from flask import request
from jinja2 import Template

# SAFE: the template is a fixed constant; user input only fills a named slot.
_GREETING = Template("Hello {{ name }}")


def render():
    name = request.args.get("name", "")
    return _GREETING.render(name=name)
