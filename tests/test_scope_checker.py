"""Tests for scope_checker.py — all is_in_scope variants + filter_file.

This is safety-critical code: 100% coverage required.
"""

import pytest

from scope_checker import (
    ScopeChecker,
    main as scope_main,
    IN_SCOPE,
    OUT_OF_SCOPE,
    NEEDS_REVIEW,
    ERROR,
)


class TestWildcardMatch:

    def test_wildcard_matches_subdomain(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://sub.target.com/path") is True

    def test_wildcard_matches_deep_subdomain(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://a.b.c.target.com") is True

    def test_wildcard_does_not_match_evil_prefix(self, scope_domains, scope_excluded):
        """Critical: *.target.com must NOT match evil-target.com."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://evil-target.com") is False

    def test_wildcard_does_not_match_apex_alone(self):
        """*.target.com should NOT match target.com (need explicit target.com in list)."""
        sc = ScopeChecker(["*.target.com"])  # no explicit target.com
        assert sc.is_in_scope("https://target.com") is False


class TestExactMatch:

    def test_exact_domain_match(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://api.target.com/v2/users") is True

    def test_apex_domain_match(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://target.com") is True


class TestExcludedDomains:

    def test_excluded_domain_blocked(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://blog.target.com") is False

    def test_excluded_takes_priority(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://status.target.com") is False


class TestOutOfScope:

    def test_completely_different_domain(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://other.com") is False

    def test_similar_domain_name(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://nottarget.com") is False


class TestEdgeCases:

    def test_empty_url(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("") is False

    def test_none_url(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope(None) is False

    def test_malformed_url(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("://broken") is False

    def test_ip_address_returns_false(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://192.168.1.1/admin") is False

    def test_ipv6_returns_false(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://[::1]/admin") is False

    def test_url_with_port(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://api.target.com:8443/endpoint") is True

    def test_case_insensitive(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("https://API.TARGET.COM/v2") is True
        assert sc.is_in_scope("https://Sub.Target.Com/path") is True

    def test_url_without_scheme(self, scope_domains, scope_excluded):
        """Bare hostnames should still work."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.is_in_scope("api.target.com") is True

    def test_url_with_path_only(self):
        sc = ScopeChecker(["target.com"])
        assert sc.is_in_scope("/just/a/path") is False


class TestVulnClassFiltering:

    def test_allowed_class(self):
        sc = ScopeChecker(["target.com"], excluded_classes=["dos", "social_engineering"])
        assert sc.is_vuln_class_allowed("idor") is True

    def test_excluded_class(self):
        sc = ScopeChecker(["target.com"], excluded_classes=["dos", "social_engineering"])
        assert sc.is_vuln_class_allowed("dos") is False

    def test_excluded_class_case_insensitive(self):
        sc = ScopeChecker(["target.com"], excluded_classes=["dos"])
        assert sc.is_vuln_class_allowed("DOS") is False


class TestFilterUrls:

    def test_split_urls(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        urls = [
            "https://api.target.com/v1",
            "https://evil.com/attack",
            "https://sub.target.com/page",
            "https://blog.target.com/post",  # excluded
        ]
        in_scope, out_of_scope = sc.filter_urls(urls)
        assert len(in_scope) == 2
        assert len(out_of_scope) == 2


class TestFilterFile:

    def test_filter_file_in_place(self, tmp_path, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        url_file = tmp_path / "urls.txt"
        url_file.write_text(
            "https://api.target.com/v1\n"
            "https://evil.com/bad\n"
            "https://sub.target.com/ok\n"
        )

        in_count, out_count = sc.filter_file(str(url_file))
        assert in_count == 2
        assert out_count == 1

        # File should now contain only in-scope URLs
        lines = url_file.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_filter_file_to_output(self, tmp_path, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        input_file = tmp_path / "input.txt"
        output_file = tmp_path / "output.txt"
        input_file.write_text("https://api.target.com/v1\nhttps://evil.com\n")

        in_count, out_count = sc.filter_file(str(input_file), str(output_file))
        assert in_count == 1
        assert out_count == 1

        # Original unchanged
        assert len(input_file.read_text().strip().split("\n")) == 2
        # Output has only in-scope
        assert len(output_file.read_text().strip().split("\n")) == 1

    def test_filter_empty_file(self, tmp_path, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        url_file = tmp_path / "empty.txt"
        url_file.write_text("")

        in_count, out_count = sc.filter_file(str(url_file))
        assert in_count == 0
        assert out_count == 0


class TestScopeCheckerCli:

    def test_cli_asset_in_scope(self, capsys):
        rc = scope_main([
            "https://api.target.com/v1",
            "--domain", "target.com",
            "--domain", "*.target.com",
        ])
        out = capsys.readouterr().out
        assert rc == 0
        assert "IN SCOPE" in out

    def test_cli_asset_out_of_scope(self, capsys):
        rc = scope_main([
            "https://evil-target.com",
            "--domain", "target.com",
            "--domain", "*.target.com",
        ])
        out = capsys.readouterr().out
        assert rc == 2
        assert "OUT OF SCOPE" in out

    def test_cli_filter_file(self, tmp_path, capsys):
        input_file = tmp_path / "urls.txt"
        output_file = tmp_path / "in_scope.txt"
        input_file.write_text(
            "https://api.target.com/v1\n"
            "https://evil.com/bad\n"
            "https://sub.target.com/ok\n"
        )

        rc = scope_main([
            "--domain", "target.com,*.target.com",
            "--input-file", str(input_file),
            "--output", str(output_file),
        ])
        out = capsys.readouterr().out

        assert rc == 0
        assert "2 in scope, 1 out of scope" in out
        assert output_file.read_text().splitlines() == [
            "https://api.target.com/v1",
            "https://sub.target.com/ok",
        ]

    def test_cli_missing_input_file_exits_cleanly(self, tmp_path, capsys):
        missing = tmp_path / "missing.txt"

        with pytest.raises(SystemExit) as exc:
            scope_main([
                "--domain", "target.com",
                "--input-file", str(missing),
            ])

        err = capsys.readouterr().err
        assert exc.value.code == 2
        assert "No such file or directory" in err


# ---------------------------------------------------------------------------
# Human-in-the-loop escalation layer (additive — does not touch is_in_scope).
# ---------------------------------------------------------------------------


class TestClassify:

    def test_classify_in_scope_allowlisted(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.classify("https://api.target.com/v2") == IN_SCOPE
        assert sc.classify("https://sub.target.com/path") == IN_SCOPE

    def test_classify_out_of_scope_excluded(self, scope_domains, scope_excluded):
        """Excluded host is a hard OUT_OF_SCOPE, even though it matches the wildcard."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.classify("https://blog.target.com/post") == OUT_OF_SCOPE
        assert sc.classify("https://status.target.com") == OUT_OF_SCOPE

    def test_classify_needs_review_unmatched_host(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.classify("https://acquired-sibling.com") == NEEDS_REVIEW
        assert sc.classify("https://evil-target.com") == NEEDS_REVIEW

    def test_classify_needs_review_ip(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.classify("https://192.168.1.1/admin") == NEEDS_REVIEW
        assert sc.classify("https://[::1]/admin") == NEEDS_REVIEW

    def test_classify_needs_review_no_scope_loaded(self):
        """No allowlist loaded → a real host is ambiguous, not auto-rejected."""
        sc = ScopeChecker([])
        assert sc.classify("https://anything.com") == NEEDS_REVIEW

    def test_classify_error_on_malformed(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.classify("") == ERROR
        assert sc.classify(None) == ERROR
        assert sc.classify("://broken") == ERROR
        assert sc.classify("/just/a/path") == ERROR

    def test_classify_matches_is_in_scope_truth(self, scope_domains, scope_excluded):
        """classify must never disagree with is_in_scope on what is IN_SCOPE."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        for url in [
            "https://api.target.com/v2",
            "https://blog.target.com",
            "https://evil-target.com",
            "https://192.168.1.1",
            "",
        ]:
            assert (sc.classify(url) == IN_SCOPE) == sc.is_in_scope(url)


class TestConfirmInScope:

    def test_confirm_in_scope_true_on_in_scope(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.confirm_in_scope("https://api.target.com/v2") is True

    def test_confirm_non_interactive_false_on_needs_review(
        self, scope_domains, scope_excluded
    ):
        """SAFE DEFAULT: ambiguous target is skipped when no human is present."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.confirm_in_scope("https://acquired-sibling.com") is False
        assert sc.confirm_in_scope("https://192.168.1.1") is False

    def test_confirm_non_interactive_false_on_excluded(
        self, scope_domains, scope_excluded
    ):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert sc.confirm_in_scope("https://blog.target.com") is False

    def test_confirm_interactive_approver_true_continues_needs_review(
        self, scope_domains, scope_excluded
    ):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert (
            sc.confirm_in_scope(
                "https://acquired-sibling.com",
                interactive=True,
                approver=lambda *_: True,
            )
            is True
        )

    def test_confirm_interactive_approver_false_skips_needs_review(
        self, scope_domains, scope_excluded
    ):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert (
            sc.confirm_in_scope(
                "https://acquired-sibling.com",
                interactive=True,
                approver=lambda *_: False,
            )
            is False
        )

    def test_confirm_excluded_never_continuable_even_with_approver(
        self, scope_domains, scope_excluded
    ):
        """Explicit exclusions are HARD: an approving human cannot continue them."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert (
            sc.confirm_in_scope(
                "https://blog.target.com",
                interactive=True,
                approver=lambda *_: True,
            )
            is False
        )

    def test_confirm_error_false_even_with_approver(self, scope_domains, scope_excluded):
        sc = ScopeChecker(scope_domains, scope_excluded)
        assert (
            sc.confirm_in_scope("", interactive=True, approver=lambda *_: True) is False
        )

    def test_confirm_approver_receives_reason(self, scope_domains, scope_excluded):
        """The approver is handed a human-readable reason for audit logging."""
        sc = ScopeChecker(scope_domains, scope_excluded)
        captured = {}

        def approver(url, reason):
            captured["url"] = url
            captured["reason"] = reason
            return True

        sc.confirm_in_scope(
            "https://acquired-sibling.com", interactive=True, approver=approver
        )
        assert captured["url"] == "https://acquired-sibling.com"
        assert "acquired-sibling.com" in captured["reason"]


class TestScopeCheckerInteractiveCli:

    def test_cli_interactive_skip_default_still_rejects(self, capsys, monkeypatch):
        """Default stdin answer (N) on NEEDS_REVIEW → SKIP, exit 2."""
        monkeypatch.setattr("builtins.input", lambda *_: "")
        rc = scope_main([
            "https://acquired-sibling.com",
            "--domain", "target.com",
            "--interactive",
        ])
        out = capsys.readouterr().out
        assert rc == 2
        assert "SKIP" in out

    def test_cli_interactive_continue_on_yes(self, capsys, monkeypatch):
        """A 'y' answer on NEEDS_REVIEW → CONTINUE override, exit 0."""
        monkeypatch.setattr("builtins.input", lambda *_: "y")
        rc = scope_main([
            "https://acquired-sibling.com",
            "--domain", "target.com",
            "--interactive",
        ])
        captured = capsys.readouterr()
        assert rc == 0
        assert "CONTINUE" in captured.out
        assert "AUDIT" in captured.err

    def test_cli_interactive_excluded_never_continues(self, capsys, monkeypatch):
        """Even answering 'y', an explicit exclusion stays OUT OF SCOPE, exit 2."""
        monkeypatch.setattr("builtins.input", lambda *_: "y")
        rc = scope_main([
            "https://blog.target.com",
            "--domain", "target.com,*.target.com",
            "--exclude-domain", "blog.target.com",
            "--interactive",
        ])
        out = capsys.readouterr().out
        assert rc == 2
        assert "OUT OF SCOPE" in out

    def test_cli_non_interactive_unchanged(self, capsys):
        """Without --interactive, behavior is the original reject (exit 2)."""
        rc = scope_main([
            "https://acquired-sibling.com",
            "--domain", "target.com",
        ])
        out = capsys.readouterr().out
        assert rc == 2
        assert "OUT OF SCOPE" in out
