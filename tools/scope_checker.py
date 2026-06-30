"""
Deterministic scope checker — code check, not LLM judgment.

Validates URLs against an allowlist of domain patterns before any outbound request.
Uses anchored suffix matching (not raw fnmatch) to prevent subdomain confusion:
  - "*.target.com" matches "sub.target.com" but NOT "evil-target.com"
  - "target.com" matches exactly "target.com"

Known limitation: IP addresses and CIDR ranges are NOT supported (returns False + warning).

SAFETY MODEL (human-in-the-loop escalation):
  `is_in_scope(url) -> bool` is the deterministic, fail-closed core and never changes:
  it returns True ONLY for an allowlisted, non-excluded host and False for everything
  else (exclusions, IPs/CIDRs, malformed, no-scope).

  A program often owns many assets (siblings, acquisitions) that are NOT in the
  configured allowlist yet may still be in-authorization. Silently dropping those can
  make the hunter miss real findings. So we ADD a triage layer on top — WITHOUT
  weakening the core:
    - classify(url) splits is_in_scope's "False" into three buckets: hard-forbidden
      (OUT_OF_SCOPE, explicit exclusions — NEVER continuable), ambiguous (NEEDS_REVIEW),
      and malformed (ERROR).
    - confirm_in_scope(url, interactive=..., approver=...) lets a human escalate a
      NEEDS_REVIEW target to "continue", while explicit exclusions stay blocked and the
      default (non-interactive / autopilot / CI) stays fail-closed (skip).

  Continuing on NEEDS_REVIEW is an explicit, human-authorized override and SHOULD be
  audit-logged by the caller. Explicit exclusions are never continuable.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import sys
import argparse
import json
from typing import Callable
from urllib.parse import urlparse

# classify() verdicts.
IN_SCOPE = "IN_SCOPE"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
NEEDS_REVIEW = "NEEDS_REVIEW"
ERROR = "ERROR"


class ScopeChecker:
    """Deterministic scope validator for bug bounty targets."""

    def __init__(
        self,
        domains: list[str],
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
    ):
        """
        Args:
            domains: Allowlist patterns like ["*.target.com", "api.target.com"]
            excluded_domains: Blocklist patterns like ["blog.target.com"]
            excluded_classes: Vuln classes excluded by program (e.g., ["dos"])
        """
        self.domains = [d.lower() for d in domains]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL's hostname is in scope.

        Returns:
            True if the hostname matches an allowed pattern and is not excluded.
            False otherwise (including for malformed URLs, empty input, IP addresses).
        """
        if not url or not isinstance(url, str):
            return False

        # Ensure we have a scheme for urlparse
        normalized = url if "://" in url else f"https://{url}"

        try:
            parsed = urlparse(normalized)
        except Exception:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        hostname = hostname.lower()

        # IP address check — not supported, return False with warning
        if _is_ip(hostname):
            print(
                f"WARNING: scope checker does not support IP addresses: {hostname}",
                file=sys.stderr,
            )
            return False

        # Strip port if present (urlparse handles this, but be safe)
        # hostname from urlparse should already exclude port

        # Check exclusion list first
        for excluded in self.excluded_domains:
            if _domain_matches(hostname, excluded):
                return False

        # Check allowlist
        for pattern in self.domains:
            if _domain_matches(hostname, pattern):
                return True

        return False

    def classify(self, url: str) -> str:
        """Triage a URL into a verdict that distinguishes forbidden from ambiguous.

        This reuses the SAME deterministic matching as is_in_scope (anchored-suffix,
        exclusions-before-allowlist, IP/CIDR refused). It does NOT relax is_in_scope;
        it only splits is_in_scope's single "False" outcome into finer buckets so a
        human can be asked about the ambiguous ones.

        Returns one of:
            "IN_SCOPE"     — allowlisted host and not excluded (is_in_scope is True).
            "OUT_OF_SCOPE" — host matches an explicit exclusion. HARD block, never
                             reviewable / never continuable.
            "NEEDS_REVIEW" — ambiguous: a parseable host that simply isn't in the
                             allowlist, an IP/CIDR, an unparseable-but-present target,
                             or no scope was loaded. These are the is_in_scope==False
                             cases that are AMBIGUOUS rather than forbidden, and may be
                             escalated to a human.
            "ERROR"        — empty / non-string / malformed url with no host at all.
        """
        if not url or not isinstance(url, str):
            return ERROR

        # Ensure we have a scheme for urlparse (mirrors is_in_scope exactly).
        normalized = url if "://" in url else f"https://{url}"

        try:
            parsed = urlparse(normalized)
        except Exception:
            # A present-but-unparseable target is ambiguous, not malformed-empty:
            # escalate to a human rather than silently treating it as an error.
            return NEEDS_REVIEW

        hostname = parsed.hostname
        if not hostname:
            # Truly malformed/empty (e.g. "://broken", "/just/a/path"): no host.
            return ERROR

        hostname = hostname.lower()

        # IP / CIDR: refused by is_in_scope, but ambiguous (could be an in-auth asset),
        # so route to human review rather than a hard reject.
        if _is_ip(hostname):
            return NEEDS_REVIEW

        # Exclusions first — explicit exclusions are a HARD, non-continuable block.
        for excluded in self.excluded_domains:
            if _domain_matches(hostname, excluded):
                return OUT_OF_SCOPE

        # Allowlist match → in scope.
        for pattern in self.domains:
            if _domain_matches(hostname, pattern):
                return IN_SCOPE

        # Parseable host, not excluded, not allowlisted (includes the no-scope-loaded
        # case where self.domains is empty): ambiguous → human review.
        return NEEDS_REVIEW

    def confirm_in_scope(
        self,
        url: str,
        *,
        interactive: bool = False,
        approver: Callable[[str, str], bool] | None = None,
    ) -> bool:
        """Confirm whether hunting `url` is authorized, escalating ambiguity to a human.

        SAFETY MODEL — fail-closed by default:
            IN_SCOPE      → True.
            OUT_OF_SCOPE  → False (explicit exclusion; NEVER continuable, even
                            interactively with an approving approver).
            ERROR         → False.
            NEEDS_REVIEW  → ambiguous target; the decision is escalated to a human:
                * interactive + approver given → return approver(url, reason); this is
                  the wiring point for AskUserQuestion / any custom UI.
                * interactive + no approver    → prompt on stdin and return the y/N
                  answer (default N).
                * NOT interactive              → return False. This is the SAFE DEFAULT
                  that preserves fail-closed behavior for autopilot / CI where no human
                  is present.

        Returning True for a NEEDS_REVIEW target is an explicit human override. Callers
        SHOULD audit-log such overrides (the `reason` passed to the approver and used in
        the prompt describes why the target was ambiguous).
        """
        verdict = self.classify(url)

        if verdict == IN_SCOPE:
            return True
        # OUT_OF_SCOPE (hard exclusion) and ERROR are never continuable.
        if verdict in (OUT_OF_SCOPE, ERROR):
            return False

        # verdict == NEEDS_REVIEW — ambiguous, eligible for human escalation.
        reason = self._review_reason(url)
        if not interactive:
            # No human present → safe default (skip). Preserves fail-closed autopilot/CI.
            return False

        if approver is not None:
            # Caller-supplied decision hook (e.g. AskUserQuestion). Audit at call site.
            return bool(approver(url, reason))

        # Interactive stdin fallback prompt; default is N (skip).
        try:
            answer = input(
                f"⚠ {url} is not in the configured scope ({reason}). "
                "Continue anyway? [y/N] "
            )
        except EOFError:
            return False
        return answer.strip().lower() in ("y", "yes")

    def _review_reason(self, url: str) -> str:
        """Human-readable reason a target landed in NEEDS_REVIEW (for prompt + audit)."""
        if not url or not isinstance(url, str):
            return "empty or non-string target"

        normalized = url if "://" in url else f"https://{url}"
        try:
            parsed = urlparse(normalized)
        except Exception:
            return "target could not be parsed"

        hostname = parsed.hostname
        if not hostname:
            return "no hostname could be parsed"

        hostname = hostname.lower()
        if _is_ip(hostname):
            return f"{hostname} is an IP/CIDR target (not supported by allowlist matching)"
        if not self.domains:
            return "no scope is loaded"
        return f"{hostname} is not in the configured allowlist"

    def is_vuln_class_allowed(self, vuln_class: str) -> bool:
        """Check if a vulnerability class is allowed by the program."""
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a list of URLs into (in_scope, out_of_scope)."""
        in_scope = []
        out_of_scope = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                out_of_scope.append(url)
        return in_scope, out_of_scope

    def filter_file(self, input_path: str, output_path: str | None = None) -> tuple[int, int]:
        """Filter a file of URLs (one per line) through scope check.

        Args:
            input_path: Path to file with URLs, one per line.
            output_path: If provided, write in-scope URLs here. If None, filter in-place.

        Returns:
            (in_scope_count, out_of_scope_count)
        """
        with open(input_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        in_scope, out_of_scope = self.filter_urls(lines)

        dest = output_path or input_path
        with open(dest, "w") as f:
            for url in in_scope:
                f.write(url + "\n")

        if out_of_scope:
            print(
                f"WARNING: filtered {len(out_of_scope)} out-of-scope URLs from {input_path}",
                file=sys.stderr,
            )

        return len(in_scope), len(out_of_scope)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Anchored domain matching — prevents subdomain confusion.

    *.target.com  → matches sub.target.com, a.b.target.com
                  → does NOT match target.com, evil-target.com
    target.com    → matches target.com exactly
    """
    if pattern.startswith("*."):
        # Wildcard: must be a proper subdomain
        suffix = pattern[1:]  # ".target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    else:
        # Exact match
        return hostname == pattern


def _is_ip(hostname: str) -> bool:
    """Check if hostname looks like an IP address (v4 or v6)."""
    # IPv6 in brackets
    if hostname.startswith("[") or ":" in hostname:
        return True
    # IPv4
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


def classify(
    url: str,
    domains: list[str],
    excluded_domains: list[str] | None = None,
) -> str:
    """Module-level wrapper around ScopeChecker.classify (see that method)."""
    return ScopeChecker(domains, excluded_domains).classify(url)


def confirm_in_scope(
    url: str,
    domains: list[str],
    excluded_domains: list[str] | None = None,
    *,
    interactive: bool = False,
    approver: Callable[[str, str], bool] | None = None,
) -> bool:
    """Module-level wrapper around ScopeChecker.confirm_in_scope (see that method)."""
    return ScopeChecker(domains, excluded_domains).confirm_in_scope(
        url, interactive=interactive, approver=approver
    )


def _split_patterns(values: list[str]) -> list[str]:
    """Expand comma-separated CLI pattern args while preserving order."""
    patterns: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                patterns.append(part)
    return patterns


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministically check assets against bug bounty scope."
    )
    parser.add_argument("asset", nargs="?", help="URL or hostname to check")
    parser.add_argument(
        "--domain",
        "-d",
        action="append",
        default=[],
        help="Allowed domain pattern. Repeat or comma-separate, e.g. target.com,*.target.com",
    )
    parser.add_argument(
        "--exclude-domain",
        "-x",
        action="append",
        default=[],
        help="Excluded domain pattern. Repeat or comma-separate.",
    )
    parser.add_argument(
        "--exclude-class",
        action="append",
        default=[],
        help="Excluded vulnerability class. Repeat or comma-separate.",
    )
    parser.add_argument("--vuln-class", help="Optional vulnerability class to check")
    parser.add_argument("--input-file", help="Filter URLs from a file, one per line")
    parser.add_argument("--output", help="Output path for filtered in-scope URLs")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument(
        "--interactive",
        "--confirm",
        dest="interactive",
        action="store_true",
        help=(
            "On an ambiguous (NEEDS_REVIEW) asset, prompt the human to continue/skip "
            "instead of silently rejecting. SAFETY: default is fail-closed; "
            "'continue' on NEEDS_REVIEW is an explicit, audited human override; "
            "explicit exclusions (OUT_OF_SCOPE) are NEVER continuable."
        ),
    )
    args = parser.parse_args(argv)

    domains = _split_patterns(args.domain)
    excluded_domains = _split_patterns(args.exclude_domain)
    excluded_classes = _split_patterns(args.exclude_class)

    if not domains:
        parser.error("at least one --domain pattern is required")
    if not args.asset and not args.input_file and not args.vuln_class:
        parser.error("provide an asset, --input-file, or --vuln-class")

    checker = ScopeChecker(domains, excluded_domains, excluded_classes)
    result: dict[str, object] = {
        "domains": domains,
        "excluded_domains": excluded_domains,
        "excluded_classes": excluded_classes,
    }
    exit_code = 0

    if args.asset:
        in_scope = checker.is_in_scope(args.asset)
        result["asset"] = args.asset
        result["in_scope"] = in_scope
        if args.interactive:
            # Triage layer: distinguish hard-forbidden from ambiguous and let a human
            # escalate the ambiguous ones. Fail-closed core (is_in_scope) is untouched.
            verdict = checker.classify(args.asset)
            result["verdict"] = verdict
            if verdict == IN_SCOPE:
                exit_code = 0
            elif verdict == NEEDS_REVIEW:
                reason = checker._review_reason(args.asset)
                result["review_reason"] = reason
                # Human override is audited at the decision point.
                proceed = checker.confirm_in_scope(args.asset, interactive=True)
                result["human_override"] = proceed
                if proceed:
                    print(
                        f"AUDIT: human authorized continue on NEEDS_REVIEW asset "
                        f"{args.asset} ({reason})",
                        file=sys.stderr,
                    )
                    exit_code = 0
                else:
                    exit_code = 2
            else:  # OUT_OF_SCOPE (hard, never continuable) or ERROR
                exit_code = 2
        elif not in_scope:
            exit_code = 2

    if args.vuln_class:
        allowed = checker.is_vuln_class_allowed(args.vuln_class)
        result["vuln_class"] = args.vuln_class
        result["vuln_class_allowed"] = allowed
        if not allowed:
            exit_code = 2

    if args.input_file:
        try:
            in_count, out_count = checker.filter_file(args.input_file, args.output)
        except OSError as exc:
            parser.error(str(exc))
        result["input_file"] = args.input_file
        result["output"] = args.output or args.input_file
        result["in_scope_count"] = in_count
        result["out_of_scope_count"] = out_count

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if "asset" in result:
            if args.interactive:
                # Reflect the triage verdict and any human override.
                if result.get("verdict") == NEEDS_REVIEW:
                    label = (
                        "CONTINUE (human override)"
                        if result.get("human_override")
                        else "SKIP (needs review)"
                    )
                else:
                    label = "IN SCOPE" if result["in_scope"] else "OUT OF SCOPE"
            else:
                label = "IN SCOPE" if result["in_scope"] else "OUT OF SCOPE"
            print(f"{label}: {result['asset']}")
        if "vuln_class" in result:
            verdict = "ALLOWED" if result["vuln_class_allowed"] else "EXCLUDED"
            print(f"{verdict}: vulnerability class {result['vuln_class']}")
        if "input_file" in result:
            print(
                "Filtered URLs: "
                f"{result['in_scope_count']} in scope, "
                f"{result['out_of_scope_count']} out of scope -> {result['output']}"
            )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
