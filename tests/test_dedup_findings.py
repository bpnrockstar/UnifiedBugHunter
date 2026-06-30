"""Tests for tools/dedup_findings.py — the deterministic dedup / cluster engine.

Functions are imported directly via the bare-module path that tests/conftest.py
sets up (it inserts tools/ on sys.path). stdlib + pytest only.

Coverage:
  - normalize_endpoint: numeric->{n}, UUID->{uuid}, long-hex/opaque-id->{id},
    host lowercased + scheme/port/userinfo stripped, query VALUES dropped while
    param NAMES are kept (by finding_key, not the endpoint string), plain route
    words preserved, empty / non-string handling, determinism.
  - finding_key: stability (two findings differing only by a numeric id collapse
    to the same key) and conservativeness (different vuln_class OR a different
    param set do NOT collapse).
  - cluster_findings: 3 findings -> 2 clusters with the right representatives,
    counts, and ordering; synthetic ids; type guards.
  - dedup_against: correctly splits new vs duplicate_of_submitted, with stable
    matched-submitted ids and counts.
  - CLI main(): {"findings": [...]} wrapper, --out (trailing newline), --json,
    --against, and argparse error exits.
"""

import io
import json
import contextlib

import pytest

from dedup_findings import (
    normalize_endpoint,
    finding_key,
    cluster_findings,
    dedup_against,
    main,
)


# ─── normalize_endpoint ──────────────────────────────────────────────────────────
class TestNormalizeEndpoint:

    def test_spec_example_full_url(self):
        """The canonical docstring example: numeric->{n}, UUID->{uuid}, host lower."""
        url = (
            "https://api.X.com/v1/users/123/orders/"
            "9f1c8e4a-1b2c-3d4e-5f60-708192a3b4c5"
        )
        assert normalize_endpoint(url) == "api.x.com/v1/users/{n}/orders/{uuid}"

    def test_numeric_segment_to_n(self):
        assert normalize_endpoint("/v1/users/123") == "/v1/users/{n}"

    def test_multiple_numeric_segments(self):
        assert normalize_endpoint("/a/1/b/2/c/3") == "/a/{n}/b/{n}/c/{n}"

    def test_uuid_segment_to_uuid(self):
        uuid = "9f1c8e4a-1b2c-3d4e-5f60-708192a3b4c5"
        assert normalize_endpoint(f"/objects/{uuid}") == "/objects/{uuid}"

    def test_uuid_case_insensitive(self):
        uuid = "9F1C8E4A-1B2C-3D4E-5F60-708192A3B4C5"
        assert normalize_endpoint(f"/o/{uuid}") == "/o/{uuid}"

    def test_long_hex_blob_to_id(self):
        """A >=12 char pure-hex segment (sha/object id) collapses to {id}."""
        assert normalize_endpoint("/objects/abcdef0123456789") == "/objects/{id}"

    def test_embedded_numeric_run_to_id(self):
        """An alnum token carrying a 3+ digit run (ORD000123) is a volatile id."""
        assert normalize_endpoint("/items/ORD000123") == "/items/{id}"

    def test_base64ish_with_digit_to_id(self):
        """A >=16 char base64url-ish token containing a digit collapses to {id}."""
        assert normalize_endpoint("/t/aGVsbG8xMjM0NTY3ODkw") == "/t/{id}"

    def test_plain_route_word_preserved(self):
        """Ordinary long path words must NOT be flattened (no digit, not hex)."""
        assert (
            normalize_endpoint("/v1/users/notifications/subscriptions")
            == "/v1/users/notifications/subscriptions"
        )

    def test_host_is_lowercased(self):
        assert normalize_endpoint("https://API.X.COM/a").startswith("api.x.com")

    def test_path_is_lowercased(self):
        assert normalize_endpoint("/V2/Cart/Items/") == "/v2/cart/items"

    def test_port_stripped_from_host(self):
        """api.x.com:443 must normalize identically to api.x.com."""
        assert normalize_endpoint("https://api.x.com:443/v1/a") == "api.x.com/v1/a"

    def test_userinfo_stripped_from_host(self):
        assert normalize_endpoint("https://user:pw@host.com/a") == "host.com/a"

    def test_scheme_dropped(self):
        """http vs https must not change the signature."""
        assert normalize_endpoint("http://api.x.com/a") == normalize_endpoint(
            "https://api.x.com/a"
        )

    def test_query_dropped_from_endpoint_string(self):
        """Query VALUES (and the whole query string) leave the endpoint signature."""
        assert normalize_endpoint("/v1/users/123/orders?sort=asc") == "/v1/users/{n}/orders"

    def test_query_value_change_does_not_change_endpoint(self):
        assert normalize_endpoint("/a?x=1") == normalize_endpoint("/a?x=99999")

    def test_scheme_less_authority_detected(self):
        """A scheme-less value that starts with a host is treated as a host."""
        assert normalize_endpoint("api.x.com/v1/users/123") == "api.x.com/v1/users/{n}"

    def test_duplicate_slashes_collapsed(self):
        assert normalize_endpoint("https://host.com/a//b/") == "host.com/a/b"

    def test_trailing_slash_dropped(self):
        assert normalize_endpoint("/v1/cart/") == "/v1/cart"

    def test_leading_slash_preserved_for_pathonly(self):
        assert normalize_endpoint("/v1/cart").startswith("/")

    def test_empty_string_returns_empty(self):
        assert normalize_endpoint("") == ""

    def test_whitespace_only_returns_empty(self):
        assert normalize_endpoint("   ") == ""

    def test_none_returns_empty(self):
        assert normalize_endpoint(None) == ""

    def test_non_string_returns_empty(self):
        assert normalize_endpoint(123) == ""

    def test_deterministic_repeat(self):
        url = "https://API.x.com/v1/users/123/orders?z=1"
        assert normalize_endpoint(url) == normalize_endpoint(url)


# ─── finding_key ─────────────────────────────────────────────────────────────────
class TestFindingKeyStability:

    def test_returns_three_tuple(self):
        key = finding_key({"id": "A", "vuln_class": "idor", "endpoint": "/u/1"})
        assert isinstance(key, tuple)
        assert len(key) == 3
        vuln_class, endpoint, params = key
        assert vuln_class == "idor"
        assert endpoint == "/u/{n}"
        assert params == ()

    def test_key_is_hashable(self):
        key = finding_key({"id": "A", "vuln_class": "idor", "endpoint": "/u/1"})
        assert {key: 1}[key] == 1  # usable as a dict key

    def test_numeric_id_only_difference_collapses(self):
        """Two findings differing ONLY by a numeric path id share one key."""
        a = {
            "id": "JIRA-1",
            "vuln_class": "idor",
            "url": "https://api.x.com/v1/users/123/orders?sort=asc",
        }
        b = {
            "id": "JIRA-2",
            "vuln_class": "idor",
            "url": "https://api.x.com/v1/users/999/orders?sort=desc",
        }
        assert finding_key(a) == finding_key(b)

    def test_query_value_difference_collapses(self):
        a = {"vuln_class": "idor", "url": "/a/1?token=abc"}
        b = {"vuln_class": "idor", "url": "/a/2?token=xyz"}
        assert finding_key(a) == finding_key(b)

    def test_bug_class_alias_equals_vuln_class(self):
        a = {"vuln_class": "idor", "endpoint": "/u/5"}
        b = {"bug_class": "IDOR", "endpoint": "/u/9"}
        assert finding_key(a) == finding_key(b)

    def test_endpoint_alias_equals_url(self):
        a = {"vuln_class": "xss", "url": "https://h.com/a/1"}
        b = {"vuln_class": "xss", "endpoint": "https://h.com/a/2"}
        assert finding_key(a) == finding_key(b)

    def test_url_preferred_over_endpoint(self):
        """When both present, 'url' wins as the endpoint source."""
        f = {"vuln_class": "xss", "url": "/from-url/1", "endpoint": "/from-endpoint/2"}
        assert finding_key(f)[1] == "/from-url/{n}"

    def test_vuln_class_separator_normalization(self):
        """'SQL Injection' / 'sql_injection' / 'sql-injection' normalize equal."""
        keys = {
            finding_key({"vuln_class": v, "endpoint": "/x"})[0]
            for v in ("SQL Injection", "sql_injection", "sql-injection", "  SQL  Injection ")
        }
        assert len(keys) == 1

    def test_param_from_string(self):
        assert finding_key({"vuln_class": "x", "endpoint": "/a", "param": "id"})[2] == ("id",)

    def test_param_comma_split_sorted(self):
        params = finding_key({"vuln_class": "x", "endpoint": "/a", "param": "z, a, m"})[2]
        assert params == ("a", "m", "z")

    def test_params_list_alias(self):
        params = finding_key({"vuln_class": "x", "endpoint": "/a", "params": ["b", "a"]})[2]
        assert params == ("a", "b")

    def test_query_param_names_kept_in_key(self):
        """Param NAMES from the query string are kept even though VALUES are dropped."""
        params = finding_key({"vuln_class": "x", "url": "/a?q=1&debug=2"})[2]
        assert params == ("debug", "q")


class TestFindingKeyConservative:

    def test_different_vuln_class_does_not_collapse(self):
        a = {"vuln_class": "idor", "url": "https://api.x.com/v1/users/123/orders"}
        b = {"vuln_class": "xss", "url": "https://api.x.com/v1/users/123/orders"}
        assert finding_key(a) != finding_key(b)

    def test_different_param_set_does_not_collapse(self):
        a = {"vuln_class": "x", "endpoint": "/a", "param": "id"}
        b = {"vuln_class": "x", "endpoint": "/a", "param": "id,page"}
        assert finding_key(a) != finding_key(b)

    def test_sqli_pair_stays_distinct_host_and_params(self):
        """Spec case: /search?q  vs  api.shop.com/search?q&debug must stay distinct.

        Different host presence (path-only vs api.shop.com) AND a different param
        set (q vs debug,q) — the key is conservative and keeps them apart.
        """
        a = {"id": "JIRA-103", "vuln_class": "sqli", "endpoint": "/search", "param": "q"}
        b = {
            "id": "JIRA-104",
            "vuln_class": "sqli",
            "url": "api.shop.com/search?q=x&debug=1",
        }
        ka, kb = finding_key(a), finding_key(b)
        assert ka != kb
        # the endpoint signatures differ (host presence) ...
        assert ka[1] == "/search"
        assert kb[1] == "api.shop.com/search"
        # ... and so do the param sets.
        assert ka[2] == ("q",)
        assert kb[2] == ("debug", "q")

    def test_different_endpoint_shape_does_not_collapse(self):
        a = {"vuln_class": "x", "endpoint": "/a/1/b"}
        b = {"vuln_class": "x", "endpoint": "/a/1/c"}
        assert finding_key(a) != finding_key(b)

    def test_non_dict_raises_type_error(self):
        with pytest.raises(TypeError):
            finding_key(["not", "a", "dict"])


# ─── cluster_findings ────────────────────────────────────────────────────────────
class TestClusterFindings:

    @pytest.fixture
    def three_findings(self):
        """3 findings: two IDORs that collapse + one distinct SQLi -> 2 clusters."""
        return [
            {
                "id": "JIRA-101",
                "vuln_class": "idor",
                "url": "https://api.x.com/v1/users/123/orders?sort=asc",
                "title": "IDOR on order lookup",
            },
            {
                "id": "JIRA-102",
                "vuln_class": "idor",
                "url": "https://api.x.com/v1/users/999/orders?sort=desc",
                "title": "IDOR variant",
            },
            {
                "id": "JIRA-103",
                "vuln_class": "sqli",
                "endpoint": "/search",
                "param": "q",
                "title": "SQLi in search",
            },
        ]

    def test_three_findings_two_clusters(self, three_findings):
        result = cluster_findings(three_findings)
        assert result["total"] == 3
        assert result["unique_count"] == 2
        assert result["duplicate_count"] == 1
        assert len(result["clusters"]) == 2

    def test_clusters_ordered_largest_first(self, three_findings):
        clusters = cluster_findings(three_findings)["clusters"]
        assert clusters[0]["count"] == 2  # the merged IDOR cluster leads
        assert clusters[1]["count"] == 1

    def test_idor_cluster_membership_and_representative(self, three_findings):
        idor = cluster_findings(three_findings)["clusters"][0]
        assert idor["ids"] == ["JIRA-101", "JIRA-102"]
        # representative = lexicographically smallest id form
        assert idor["representative"] == "JIRA-101"
        assert idor["count"] == 2
        assert idor["title"] == "IDOR on order lookup"
        assert idor["key"][0] == "idor"

    def test_sqli_cluster_singleton(self, three_findings):
        sqli = cluster_findings(three_findings)["clusters"][1]
        assert sqli["ids"] == ["JIRA-103"]
        assert sqli["representative"] == "JIRA-103"
        assert sqli["count"] == 1
        assert sqli["key"][0] == "sqli"

    def test_representative_is_lexicographically_smallest(self):
        """Representative must be the smallest str(id), regardless of input order."""
        findings = [
            {"id": "ZZZ", "vuln_class": "x", "endpoint": "/a"},
            {"id": "AAA", "vuln_class": "x", "endpoint": "/a"},
            {"id": "MMM", "vuln_class": "x", "endpoint": "/a"},
        ]
        cluster = cluster_findings(findings)["clusters"][0]
        assert cluster["representative"] == "AAA"

    def test_ids_preserve_input_order_within_cluster(self):
        findings = [
            {"id": "ZZZ", "vuln_class": "x", "endpoint": "/a"},
            {"id": "AAA", "vuln_class": "x", "endpoint": "/a"},
        ]
        cluster = cluster_findings(findings)["clusters"][0]
        assert cluster["ids"] == ["ZZZ", "AAA"]  # input order, not sorted

    def test_synthetic_id_when_missing(self):
        result = cluster_findings([{"vuln_class": "xss", "endpoint": "/a"}])
        assert result["clusters"][0]["representative"] == "_idx_0"

    def test_title_none_when_absent(self):
        result = cluster_findings([{"id": "X", "vuln_class": "xss", "endpoint": "/a"}])
        assert result["clusters"][0]["title"] is None

    def test_key_param_is_list_not_tuple(self):
        """JSON-friendly: the param slice of the serialized key is a list."""
        result = cluster_findings(
            [{"id": "X", "vuln_class": "x", "endpoint": "/a", "param": "id"}]
        )
        assert result["clusters"][0]["key"][2] == ["id"]

    def test_empty_list(self):
        result = cluster_findings([])
        assert result == {
            "clusters": [],
            "unique_count": 0,
            "total": 0,
            "duplicate_count": 0,
        }

    def test_deterministic_repeat(self, three_findings):
        assert cluster_findings(three_findings) == cluster_findings(three_findings)

    def test_non_list_raises_type_error(self):
        with pytest.raises(TypeError):
            cluster_findings({"not": "a list"})

    def test_non_dict_member_raises_type_error(self):
        with pytest.raises(TypeError):
            cluster_findings([{"vuln_class": "x", "endpoint": "/a"}, "bad"])


# ─── dedup_against ───────────────────────────────────────────────────────────────
class TestDedupAgainst:

    @pytest.fixture
    def findings(self):
        return [
            {
                "id": "NEW-1",
                "vuln_class": "idor",
                "url": "https://api.x.com/v1/users/123/orders?sort=asc",
            },
            {
                "id": "NEW-2",
                "vuln_class": "idor",
                "url": "https://api.x.com/v1/users/999/orders?sort=desc",
            },
            {"id": "NEW-3", "vuln_class": "sqli", "endpoint": "/search", "param": "q"},
        ]

    @pytest.fixture
    def submitted(self):
        # Same key shape as the NEW-1/NEW-2 IDOR cluster (different concrete id).
        return [
            {
                "id": "SUB-1",
                "vuln_class": "idor",
                "url": "https://api.x.com/v1/users/7/orders?sort=asc",
            }
        ]

    def test_splits_new_vs_duplicate(self, findings, submitted):
        result = dedup_against(findings, submitted)
        assert result["total"] == 3
        assert result["new"] == ["NEW-3"]
        assert result["new_count"] == 1
        assert result["duplicate_count"] == 2

    def test_duplicate_entries_reference_submitted(self, findings, submitted):
        result = dedup_against(findings, submitted)
        dup_ids = [d["id"] for d in result["duplicate_of_submitted"]]
        assert dup_ids == ["NEW-1", "NEW-2"]
        for d in result["duplicate_of_submitted"]:
            assert d["matched_submitted_id"] == "SUB-1"
            assert d["key"][0] == "idor"

    def test_counts_are_consistent(self, findings, submitted):
        result = dedup_against(findings, submitted)
        assert result["new_count"] == len(result["new"])
        assert result["duplicate_count"] == len(result["duplicate_of_submitted"])
        assert result["new_count"] + result["duplicate_count"] == result["total"]

    def test_empty_submitted_all_new(self, findings):
        result = dedup_against(findings, [])
        assert result["new_count"] == 3
        assert result["duplicate_count"] == 0
        assert result["new"] == ["NEW-1", "NEW-2", "NEW-3"]

    def test_all_duplicate(self):
        findings = [{"id": "A", "vuln_class": "xss", "endpoint": "/x/1"}]
        submitted = [{"id": "S", "vuln_class": "xss", "endpoint": "/x/2"}]
        result = dedup_against(findings, submitted)
        assert result["new"] == []
        assert result["duplicate_count"] == 1

    def test_matched_submitted_id_is_smallest_on_collision(self):
        """When several submitted items share a key, the smallest id is reported."""
        findings = [{"id": "F", "vuln_class": "idor", "endpoint": "/u/1"}]
        submitted = [
            {"id": "SUB-9", "vuln_class": "idor", "endpoint": "/u/2"},
            {"id": "SUB-2", "vuln_class": "idor", "endpoint": "/u/3"},
        ]
        result = dedup_against(findings, submitted)
        assert result["duplicate_of_submitted"][0]["matched_submitted_id"] == "SUB-2"

    def test_deterministic_repeat(self, findings, submitted):
        assert dedup_against(findings, submitted) == dedup_against(findings, submitted)

    def test_non_list_findings_raises(self):
        with pytest.raises(TypeError):
            dedup_against({"bad": 1}, [])

    def test_non_list_submitted_raises(self):
        with pytest.raises(TypeError):
            dedup_against([], {"bad": 1})

    def test_non_dict_submitted_member_raises(self):
        with pytest.raises(TypeError):
            dedup_against([], ["bad"])


# ─── CLI main() ──────────────────────────────────────────────────────────────────
class TestCLI:

    def _write(self, path, obj):
        path.write_text(json.dumps(obj), encoding="utf-8")
        return str(path)

    @pytest.fixture
    def findings_obj(self):
        return [
            {"id": "1", "vuln_class": "idor", "endpoint": "/u/1"},
            {"id": "2", "vuln_class": "idor", "endpoint": "/u/2"},
            {"id": "3", "vuln_class": "sqli", "endpoint": "/search", "param": "q"},
        ]

    def test_summary_run_returns_zero(self, tmp_path, findings_obj):
        fp = self._write(tmp_path / "f.json", findings_obj)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--findings", fp])
        assert rc == 0
        assert "3 findings" in buf.getvalue()

    def test_findings_wrapper_accepted(self, tmp_path, findings_obj):
        """A {"findings": [...]} wrapper is unwrapped just like a bare list."""
        fp = self._write(tmp_path / "f.json", {"findings": findings_obj})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--findings", fp, "--json"])
        assert rc == 0
        parsed = json.loads(buf.getvalue())
        assert parsed["clusters"]["total"] == 3
        assert parsed["clusters"]["unique_count"] == 2

    def test_json_flag_prints_machine_readable(self, tmp_path, findings_obj):
        fp = self._write(tmp_path / "f.json", findings_obj)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--findings", fp, "--json"])
        parsed = json.loads(buf.getvalue())
        assert set(parsed.keys()) == {"clusters"}

    def test_out_file_written_with_trailing_newline(self, tmp_path, findings_obj):
        fp = self._write(tmp_path / "f.json", findings_obj)
        outp = tmp_path / "out.json"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--findings", fp, "--out", str(outp)])
        assert rc == 0
        text = outp.read_text(encoding="utf-8")
        assert text.endswith("\n")
        parsed = json.loads(text)
        assert parsed["clusters"]["total"] == 3

    def test_against_adds_dedup_section(self, tmp_path, findings_obj):
        fp = self._write(tmp_path / "f.json", findings_obj)
        subp = self._write(
            tmp_path / "sub.json",
            [{"id": "S", "vuln_class": "idor", "endpoint": "/u/777"}],
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--findings", fp, "--against", subp, "--json"])
        parsed = json.loads(buf.getvalue())
        assert "dedup_against_submitted" in parsed
        # both /u/N idor findings match the submitted idor on /u/N.
        assert parsed["dedup_against_submitted"]["duplicate_count"] == 2
        assert parsed["dedup_against_submitted"]["new"] == ["3"]

    def test_missing_required_findings_arg_errors(self):
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code != 0

    def test_unreadable_findings_path_errors(self):
        with pytest.raises(SystemExit) as exc:
            main(["--findings", "/nonexistent/definitely/missing.json"])
        assert exc.value.code != 0

    def test_bad_json_shape_errors(self, tmp_path):
        """A top-level JSON value that is neither a list nor {'findings': [...]}."""
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"nope": 1}), encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            main(["--findings", str(bad)])
        assert exc.value.code != 0
