"""SAFE variant of command_injection.py — argv list, no shell.

Negative case: the eval expects ZERO findings for this file.
"""
import subprocess


def ping(host: str):
    # SAFE: argument vector, shell disabled — host can't break out into a command.
    return subprocess.check_output(["ping", "-c", "1", host], shell=False)
