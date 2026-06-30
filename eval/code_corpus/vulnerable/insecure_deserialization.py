# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""Insecure deserialization — pickle.loads on untrusted bytes = RCE.

Ground-truth finding: vuln_class=insecure-deserialization on the loads line below.
"""
import pickle

from flask import request


def load_session():
    blob = request.get_data()
    # VULN: pickle.loads on attacker-controlled bytes executes __reduce__ — RCE.
    return pickle.loads(blob)
