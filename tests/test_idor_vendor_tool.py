import importlib
import sys


def test_vendor_idor_tool_import_is_safe_without_env(monkeypatch):
    monkeypatch.delenv("ZENDESK_SUBDOMAIN", raising=False)
    monkeypatch.delenv("ZENDESK_EMAIL", raising=False)
    monkeypatch.delenv("ZENDESK_API_TOKEN", raising=False)

    sys.modules.pop("idor_vendor_test", None)
    mod = importlib.import_module("idor_vendor_test")

    assert mod.BASE_URL == ""
    assert mod.AUTH is None
    assert mod.validate_config() == (
        "Set ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_TOKEN env vars"
    )
