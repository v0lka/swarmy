"""Tests of ``tools.scope`` — the session target allowlist (arch §6.3, T2.1.1).

Covers the arch §6.3 matching semantics as a parameterized matrix (domain
exact/subdomain with the dot-boundary rule, ``ipaddress`` subnets, explicit
port list with scheme defaults 80/443, scheme allowlist), the fail-closed
handling of unparseable URLs, the operator-gated ``extend()`` API, and the
``invariant: out-of-scope-target`` records fed by the platform contour.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from swarmy.tools.scope import (
    DEFAULT_PORTS,
    OutOfScopeEndpoint,
    ScopeDenialKind,
    ScopeEntries,
    ScopeExtensionDenied,
    ScopeRegistry,
)


def _entries(
    domains: list[str] | None = None,
    ip_subnets: list[str] | None = None,
    ports: list[int] | None = None,
    schemes: list[str] | None = None,
) -> ScopeEntries:
    """Build config-shaped scope entries (arch §12.1)."""
    return ScopeEntries(
        domains=domains if domains is not None else [],
        ip_subnets=ip_subnets if ip_subnets is not None else [],
        ports=ports if ports is not None else [],
        schemes=schemes if schemes is not None else [],
    )


def test_default_port_constants_follow_arch() -> None:
    """The scheme defaults are exactly 80/443 (arch §6.3)."""
    assert DEFAULT_PORTS == {"http": 80, "https": 443}


@pytest.mark.parametrize(
    ("url", "expected_allowed", "expected_kind"),
    [
        ("https://example.com/", True, None),
        ("https://sub.example.com/x?q=1", True, None),
        ("https://deep.sub.example.com/", True, None),
        ("https://EXAMPLE.com/", True, None),  # case-insensitive
        ("https://example.com./", True, None),  # trailing root dot
        ("https://notexample.com/", False, ScopeDenialKind.HOST),
        ("https://evilexample.com/", False, ScopeDenialKind.HOST),  # no dot boundary
        ("https://example.com.evil.io/", False, ScopeDenialKind.HOST),
        ("https://sub.notexample.com/", False, ScopeDenialKind.HOST),
    ],
    ids=[
        "exact", "subdomain", "deep-subdomain", "case-insensitive", "root-dot",
        "notexample", "suffix-trick", "parent-of-entry", "subdomain-of-other",
    ],
)
def test_domain_match_matrix(
    url: str, expected_allowed: bool, expected_kind: ScopeDenialKind | None
) -> None:
    """Domain semantics: exact name or subordinate subdomain (arch §6.3)."""
    registry = ScopeRegistry(_entries(domains=["example.com"], ports=[443], schemes=["https"]))
    verdict = registry.check(url)
    assert verdict.allowed is expected_allowed
    assert verdict.denial_kind is expected_kind


@pytest.mark.parametrize(
    ("url", "expected_allowed"),
    [
        ("http://203.0.113.7/", True),
        ("http://203.0.113.255/x", True),
        ("http://203.0.114.1/", False),
        ("http://203.0.113.7.evil.io/", False),  # IP-looking string is a hostname
        ("http://[2001:db8::1]/", True),
        ("http://[2001:db9::1]/", False),
    ],
    ids=["v4-inside", "v4-edge", "v4-outside", "v4-lookalike", "v6-inside", "v6-outside"],
)
def test_ip_subnet_match_matrix(url: str, expected_allowed: bool) -> None:
    """IP-literal hosts resolve through ``ipaddress`` subnets (arch §6.3)."""
    registry = ScopeRegistry(
        _entries(
            ip_subnets=["203.0.113.0/24", "2001:db8::/32"],
            ports=[80],
            schemes=["http"],
        )
    )
    assert registry.check(url).allowed is expected_allowed


@pytest.mark.parametrize(
    ("url", "expected_allowed", "expected_kind"),
    [
        ("http://example.com/", True, None),  # implicit 80
        ("https://example.com/", True, None),  # implicit 443
        ("http://example.com:80/", True, None),  # explicit 80
        ("https://example.com:443/x", True, None),
        ("http://example.com:8080/", False, ScopeDenialKind.PORT),
        ("https://example.com:8081/", False, ScopeDenialKind.PORT),
    ],
    ids=["implicit-80", "implicit-443", "explicit-80", "explicit-443", "bad-8080", "bad-8081"],
)
def test_default_port_matrix(
    url: str, expected_allowed: bool, expected_kind: ScopeDenialKind | None
) -> None:
    """Port semantics: explicit list, implicit port from the scheme (arch §6.3)."""
    registry = ScopeRegistry(
        _entries(domains=["example.com"], ports=[80, 443], schemes=["http", "https"])
    )
    verdict = registry.check(url)
    assert verdict.allowed is expected_allowed
    assert verdict.denial_kind is expected_kind


def test_explicit_port_list_replaces_scheme_defaults() -> None:
    """A non-empty ``ports`` list is authoritative: implicit 80 is denied."""
    registry = ScopeRegistry(
        _entries(domains=["example.com"], ports=[8080], schemes=["http"])
    )
    assert registry.check("http://example.com:8080/").allowed is True
    verdict = registry.check("http://example.com/")
    assert verdict.allowed is False
    assert verdict.denial_kind is ScopeDenialKind.PORT


@pytest.mark.parametrize(
    ("url", "expected_allowed", "expected_kind"),
    [
        ("https://example.com/", True, None),
        ("http://example.com/", False, ScopeDenialKind.SCHEME),
        ("ftp://example.com/", False, ScopeDenialKind.SCHEME),
    ],
    ids=["https-ok", "http-denied", "ftp-denied"],
)
def test_scheme_allowlist_matrix(
    url: str, expected_allowed: bool, expected_kind: ScopeDenialKind | None
) -> None:
    """Scheme semantics: allowlist, case-normalized (arch §6.3)."""
    registry = ScopeRegistry(_entries(domains=["example.com"], ports=[443], schemes=["https"]))
    verdict = registry.check(url)
    assert verdict.allowed is expected_allowed
    assert verdict.denial_kind is expected_kind


def test_omitted_schemes_default_to_http_and_https() -> None:
    """An empty ``schemes`` list means the http/https allowlist (arch §6.3)."""
    registry = ScopeRegistry(_entries(domains=["example.com"], ports=[80, 443]))
    assert registry.check("http://example.com/").allowed is True
    assert registry.check("https://example.com/").allowed is True
    assert registry.check("ftp://example.com/").allowed is False


@pytest.mark.parametrize(
    "url",
    ["garbage", "", "http://", "//no-scheme-no-host", "http://host:bad-port/"],
    ids=["garbage", "empty", "bare-scheme", "no-host", "bad-port"],
)
def test_unparseable_urls_are_denied_not_raised(url: str) -> None:
    """Fail-closed: malformed LLM-authored URLs deny instead of raising."""
    registry = ScopeRegistry(_entries(domains=["example.com"]))
    verdict = registry.check(url)
    assert verdict.allowed is False
    assert verdict.denial_kind is ScopeDenialKind.PARSE
    assert verdict.reason is not None


def test_empty_allowlist_denies_every_host() -> None:
    """Fail-closed: no entries — no host is contactable (arch §6.3)."""
    registry = ScopeRegistry()
    assert registry.check("http://anything.example.net/").allowed is False
    assert registry.check("http://203.0.113.1/").allowed is False


def test_denial_reason_is_agent_facing() -> None:
    """A denial carries the reason the agent needs (spec §8.5, arch §6.3)."""
    registry = ScopeRegistry(_entries(domains=["example.com"], ports=[443], schemes=["https"]))
    verdict = registry.check("https://203.0.114.9/")
    assert verdict.reason is not None
    assert "203.0.114.9" in verdict.reason


def test_verdict_is_frozen() -> None:
    """ScopeVerdict is an immutable domain value (Pydantic frozen)."""
    verdict = ScopeRegistry(_entries(domains=["example.com"])).check("https://example.com/")
    with pytest.raises(ValidationError):
        verdict.allowed = False


# ---- extend(): operator-only runtime extension (arch §6.3) ----


def test_extend_requires_operator_origin() -> None:
    """Programmatic extension without origin='operator' is impossible (AC)."""
    registry = ScopeRegistry(_entries(domains=["example.com"]))
    for origin in ("crawler", "engine", "platform", ""):
        with pytest.raises(ScopeExtensionDenied, match="operator"):
            registry.extend(_entries(domains=["extra.com"]), origin=origin)
        # nothing was merged by the rejected call
        assert registry.check("https://extra.com/").allowed is False


def test_extend_with_operator_origin_merges_entries() -> None:
    """An operator decision widens the scope (arch §6.3, ScopeChanged in P3.3)."""
    registry = ScopeRegistry(_entries(domains=["example.com"], ports=[443], schemes=["https"]))
    registry.extend(
        _entries(domains=["extra.com"], ip_subnets=["203.0.113.0/24"], schemes=["http"]),
        origin="operator",
    )
    assert registry.check("https://extra.com/").allowed is True
    assert registry.check("https://203.0.113.9/").allowed is True
    # old entries survived the merge
    assert registry.check("https://example.com/").allowed is True


def test_extend_deduplicates() -> None:
    """Re-extending with the same entries does not grow the allowlist."""
    registry = ScopeRegistry(_entries(domains=["example.com"]))
    registry.extend(_entries(domains=["example.com", "extra.com"]), origin="operator")
    registry.extend(_entries(domains=["extra.com"]), origin="operator")
    assert list(registry.entries.domains) == ["example.com", "extra.com"]


# ---- out-of-scope endpoint records (invariant: out-of-scope-target) ----


def test_marked_out_of_scope_endpoint_blocks_in_allowlisted_host() -> None:
    """A marked record denies its endpoint even inside the allowlist (AC)."""
    registry = ScopeRegistry(
        _entries(domains=["target.example.com"], ports=[443], schemes=["https"])
    )
    url = "https://target.example.com/logout"
    assert registry.check(url).allowed is True  # allowlist alone permits it
    registry.mark_out_of_scope(
        [OutOfScopeEndpoint(host="target.example.com:443", method="GET", path="/logout")]
    )
    reason = registry.out_of_scope_reason(url, "GET")
    assert reason is not None
    assert "out-of-scope-target" in reason


def test_marked_endpoint_method_semantics() -> None:
    """Records are method-aware; an unknown method matches fail-closed."""
    registry = ScopeRegistry()
    registry.mark_out_of_scope(
        [OutOfScopeEndpoint(host="target.example.com:443", method="POST", path="/logout")]
    )
    assert registry.out_of_scope_reason("https://target.example.com/logout", "POST") is not None
    assert registry.out_of_scope_reason("https://target.example.com/logout", "GET") is None
    # method unknown (fail-closed): any marked record on the path blocks
    assert registry.out_of_scope_reason("https://target.example.com/logout", None) is not None


def test_marked_endpoint_path_and_query_normalization() -> None:
    """Path matching ignores query strings and folds trailing slashes."""
    registry = ScopeRegistry()
    registry.mark_out_of_scope(
        [OutOfScopeEndpoint(host="target.example.com:443", method="GET", path="/logout")]
    )
    assert registry.out_of_scope_reason("https://target.example.com/logout?q=1", "GET") is not None
    assert registry.out_of_scope_reason("https://target.example.com/logout/", "GET") is not None
    assert registry.out_of_scope_reason("https://target.example.com/logouts", "GET") is None


def test_marked_endpoint_without_port_matches_any_port() -> None:
    """A portless record host is the lenient any-port fallback (arch §4.2)."""
    registry = ScopeRegistry()
    registry.mark_out_of_scope([OutOfScopeEndpoint(host="target.example.com", path="/x")])
    assert registry.out_of_scope_reason("https://target.example.com:8443/x", "GET") is not None


def test_marked_endpoints_is_idempotent_and_readable() -> None:
    """Duplicate marking collapses; records stay readable (diagnostics)."""
    registry = ScopeRegistry()
    record = OutOfScopeEndpoint(host="target.example.com:443", method="GET", path="/logout")
    registry.mark_out_of_scope([record])
    registry.mark_out_of_scope([record])
    assert registry.marked_endpoints() == (record,)


def test_marked_records_do_not_affect_the_allowlist() -> None:
    """Marking is a restriction only: unmarked URLs of the host stay legal."""
    registry = ScopeRegistry(
        _entries(domains=["target.example.com"], ports=[443], schemes=["https"])
    )
    registry.mark_out_of_scope(
        [OutOfScopeEndpoint(host="target.example.com:443", method="GET", path="/logout")]
    )
    assert registry.check("https://target.example.com/other").allowed is True


# ---- config validation: session start fails fast (arch §4.5, §12.1) ----


@pytest.mark.parametrize(
    ("kwargs", "bad_value"),
    [
        ({"ip_subnets": ["not-a-subnet"]}, "not-a-subnet"),
        ({"ports": [0]}, 0),
        ({"ports": [70000]}, 70000),
        ({"domains": [""]}, ""),
        ({"domains": ["203.0.113.7"]}, "203.0.113.7"),  # IPs belong to ip_subnets
        ({"schemes": ["ht tp"]}, "ht tp"),
    ],
    ids=["bad-subnet", "port-zero", "port-huge", "empty-domain", "ip-in-domains", "bad-scheme"],
)
def test_scope_entries_validation_fails_fast(kwargs: dict[str, object], bad_value: object) -> None:
    """Malformed entries abort at construction, not at first use (arch §4.5)."""
    del bad_value
    with pytest.raises(ValidationError):
        ScopeEntries(**kwargs)  # type: ignore[arg-type]
