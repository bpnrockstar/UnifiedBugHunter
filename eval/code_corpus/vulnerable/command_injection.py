# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""OS command injection — user input passed to a shell.

Ground-truth finding: vuln_class=command-injection on the subprocess line below.
"""
import subprocess


def ping(host: str):
    # VULN: shell=True with interpolated input — command injection sink.
    return subprocess.check_output("ping -c 1 " + host, shell=True)
