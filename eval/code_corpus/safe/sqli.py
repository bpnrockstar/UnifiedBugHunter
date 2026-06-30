"""SAFE variant of sqli.py — parameterized query, no injection.

Negative case: the eval expects ZERO findings for this file.
"""
import sqlite3


def get_user(conn: sqlite3.Connection, user_id: str):
    cur = conn.cursor()
    # SAFE: bound parameter; the driver escapes the value.
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()
