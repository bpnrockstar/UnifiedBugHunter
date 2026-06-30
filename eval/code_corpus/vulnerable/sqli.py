# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""SQL injection — raw string interpolation of user input into a query.

Ground-truth finding: vuln_class=sqli on the cur.execute line below.
"""
import sqlite3


def get_user(conn: sqlite3.Connection, user_id: str):
    cur = conn.cursor()
    # VULN: user_id concatenated straight into SQL — classic SQLi sink.
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return cur.fetchall()
