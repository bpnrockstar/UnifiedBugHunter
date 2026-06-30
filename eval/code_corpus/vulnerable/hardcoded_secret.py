# INTENTIONALLY VULNERABLE — eval fixture, do not deploy
"""Hardcoded secret — an AWS-style secret key committed in source.

Ground-truth finding: vuln_class=hardcoded-secret on the AWS_SECRET line below.
NOTE: this is a fabricated, non-functional key used only as an eval fixture.
"""

# VULN: long-lived credential baked into source — hardcoded secret.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def client_config() -> dict:
    return {"aws_secret_access_key": AWS_SECRET_ACCESS_KEY}
