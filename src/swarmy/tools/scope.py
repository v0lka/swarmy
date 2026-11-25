"""``ScopeRegistry``: the session target allowlist (arch §6.3, T2.1.1).

The registry answers exactly one question — *may this URL be contacted?* —
and it is consulted **before every network hop** (arch §6.2/§6.3): the
initial request and each manual redirect hop re-check here.

Matching semantics (arch §6.3):

* **domain** — exact name or a subordinate subdomain: ``example.com``
  covers ``example.com`` and ``*.example.com`` (case-insensitive, trailing
  dot ignored; a *suffix* without the dot boundary — ``evilexample.com`` —
  never matches);
* **IP** — the URL host is parsed as an IP literal and must fall inside one
  of the configured ``ipaddress`` subnets (v4 or v6);
* **port** — the URL's explicit port, else the scheme default (80 for
  ``http``, 443 for ``https``), must be in the explicit list; an omitted
  port list defaults to the scheme defaults;
* **scheme** — an allowlist (``http``/``https``); an omitted scheme list
  defaults to ``{http, https}``.

Fail-closed everywhere: an empty allowlist denies every host, an
unparseable URL denies instead of raising (LLM-authored arguments are
untrusted data), and every denial carries the reason the agent needs to
correct its plan (spec §8.5).

Runtime extension (arch §6.3): ``extend()`` requires ``origin="operator"``
— the scope may grow only through an operator decision (HITL). The
``ScopeChanged`` journal event is published by the platform HITL contour
when it docks in P3.3; the registry itself stays event-free.

Out-of-scope endpoints (``invariant: out-of-scope-target``): the platform
contour feeds memory ``Endpoint`` records flagged ``out_of_scope=True``
(``host`` = full ``host:port``, arch §4.2) via :meth:`ScopeRegistry.
mark_out_of_scope`; requests to such endpoints are denied even when the
host itself is allowlisted (e.g. a specific path the operator excluded).
Marking is a *restriction*, so unlike :meth:`extend` it needs no origin
gate — the fail-closed direction is always safe to record programmatically.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from collections.abc import Sequence

#: Scheme defaults applied when a URL carries no explicit port (arch §6.3).
DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}

#: Scheme allowlist used when the config omits ``schemes`` (arch §6.3).
DEFAULT_SCHEMES: Final[tuple[str, ...]] = ("http", "https")


def _is_ip_literal(host: str) -> bool:
    """True when ``host`` parses as an IPv4/IPv6 address literal."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class ScopeEntries(BaseModel):
    """The ``scope`` section of the session config (arch §12.1, T2.1.1).

    Every list is validated fail-fast at construction (session start is
    fail-fast, arch §4.5): a malformed subnet or port aborts the session
    before the first LLM call, not at the first blocked request. An omitted
    ``ports`` list means the scheme defaults (80/443); an omitted
    ``schemes`` list means ``http``+``https``; empty ``domains`` and
    ``ip_subnets`` mean *no* host is allowed.
    """

    model_config = ConfigDict(extra="forbid")

    domains: list[str] = Field(default_factory=list)
    ip_subnets: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    schemes: list[str] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def _validate_domains(cls, value: list[str]) -> list[str]:
        """Normalize domains (lowercase, no trailing dot); reject junk.

        Bare IP literals are rejected — IP allowlisting belongs to
        ``ip_subnets`` (an IP in ``domains`` would never match, because
        IP-literal hosts are resolved through the subnet branch).
        """
        normalized: list[str] = []
        for domain in value:
            cleaned = domain.strip().lower().rstrip(".")
            if (not cleaned or ("." not in cleaned and cleaned != "localhost")) or (
                _is_ip_literal(cleaned)
            ):
                msg = f"invalid scope domain {domain!r} (IPs belong to ip_subnets)"
                raise ValueError(msg)
            normalized.append(cleaned)
        return normalized

    @field_validator("ip_subnets")
    @classmethod
    def _validate_subnets(cls, value: list[str]) -> list[str]:
        """Reject strings that are not valid IPv4/IPv6 networks."""
        for subnet in value:
            try:
                ipaddress.ip_network(subnet)
            except ValueError as error:
                msg = f"invalid scope subnet {subnet!r}: {error}"
                raise ValueError(msg) from None
        return value

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: list[int]) -> list[int]:
        """Keep ports in the 1-65535 range (fail-fast on config errors)."""
        for port in value:
            if not 1 <= port <= 65535:
                msg = f"scope port out of range: {port}"
                raise ValueError(msg)
        return value

    @field_validator("schemes")
    @classmethod
    def _validate_schemes(cls, value: list[str]) -> list[str]:
        """Normalize schemes to lowercase tokens."""
        for scheme in value:
            if not scheme.isalnum():
                msg = f"invalid scope scheme {scheme!r}"
                raise ValueError(msg)
        return [scheme.lower() for scheme in value]


class ScopeDenialKind(StrEnum):
    """Why a URL failed the allowlist (diagnostics of :class:`ScopeVerdict`)."""

    PARSE = "parse"  # URL is malformed/unparseable — never contacted
    SCHEME = "scheme"  # scheme outside the allowlist
    HOST = "host"  # host outside domains/ip_subnets (incl. empty allowlist)
    PORT = "port"  # port outside the explicit list / no scheme default


class ScopeVerdict(BaseModel):
    """Result of one scope check (arch §6.3: ``allowed | denied(reason)``).

    ``reason`` is set exactly when ``allowed`` is ``False``; it is worded
    for the agent (spec §8.5) and becomes the ``invariant: scope`` denial
    feedback.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    denial_kind: ScopeDenialKind | None = None
    reason: str | None = None

    @classmethod
    def allow(cls) -> ScopeVerdict:
        """Build the allow verdict."""
        return cls(allowed=True)

    @classmethod
    def deny(cls, kind: ScopeDenialKind, reason: str) -> ScopeVerdict:
        """Build a denial with its kind and agent-facing reason."""
        return cls(allowed=False, denial_kind=kind, reason=reason)


class OutOfScopeEndpoint(BaseModel):
    """One endpoint record flagged ``out_of_scope=True`` (arch §4.2, §6.3).

    Mirrors the memory ``Endpoint`` key: ``host`` carries the full
    ``host:port`` and ``method``/``path`` complete the unique endpoint
    identity. ``method="*"`` marks every method of the path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str  # full host:port, e.g. "target.example.com:8443"
    method: str = "*"
    path: str = "/"

    @field_validator("method")
    @classmethod
    def _validate_method(cls, value: str) -> str:
        """Accept ``*`` or an HTTP verb, normalized to uppercase."""
        cleaned = value.strip().upper()
        if cleaned != "*" and not cleaned.isalpha():
            msg = f"invalid endpoint method {value!r}"
            raise ValueError(msg)
        return cleaned

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        """Normalize the path (empty folds to ``/``, trailing slash drops)."""
        cleaned = value.strip() or "/"
        if cleaned != "/" and cleaned.endswith("/"):
            cleaned = cleaned.rstrip("/") or "/"
        return cleaned


class ScopeExtensionDenied(ValueError):
    """Raised when the scope is extended without ``origin="operator"``.

    The allowlist may only grow through an operator decision (arch §6.3,
    spec §7.2): any programmatic extension attempt is rejected *before*
    the entries are merged.
    """


def _normalized_domain(host: str) -> str:
    """Lowercase a hostname and drop the trailing root dot."""
    return host.strip().lower().rstrip(".")


def _normalized_path(path: str) -> str:
    """Fold a URL path to its canonical form (empty ↔ ``/``, no trailing slash)."""
    cleaned = path or "/"
    if cleaned != "/" and cleaned.endswith("/"):
        cleaned = cleaned.rstrip("/") or "/"
    return cleaned


def _host_port_of(netloc_host: str, port: int) -> str:
    """Build the ``host:port`` key used by endpoint records (arch §4.2)."""
    return f"{_normalized_domain(netloc_host)}:{port}"


def _split_record_host(record_host: str) -> tuple[str, int | None]:
    """Split an endpoint record ``host`` into ``(hostname, port | None)``.

    Handles the IPv6 bracket form (``[::1]:8443``); a missing or
    non-numeric port yields ``None`` (the lenient any-port fallback).
    """
    candidate = record_host.strip()
    if candidate.startswith("[") and "]" in candidate:
        host, _, rest = candidate[1:].partition("]")
        rest = rest.lstrip(":")
        return _normalized_domain(host), int(rest) if rest.isdigit() else None
    bare, _, port_part = candidate.rpartition(":")
    if bare and port_part.isdigit():
        return _normalized_domain(bare), int(port_part)
    return _normalized_domain(candidate), None


class _CompiledScope:
    """Pre-parsed allowlist (domains, networks, ports, schemes).

    Rebuilt on every mutation so ``check`` never parses user input on the
    hot path; construction fails fast through :class:`ScopeEntries`.
    """

    __slots__ = ("domains", "networks", "ports", "schemes")

    def __init__(self, entries: ScopeEntries) -> None:
        """Compile the entries (subnet strings parse exactly once)."""
        self.domains: tuple[str, ...] = tuple(dict.fromkeys(entries.domains))
        self.networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
            dict.fromkeys(ipaddress.ip_network(subnet) for subnet in entries.ip_subnets)
        )
        self.schemes: frozenset[str] = frozenset(
            entries.schemes if entries.schemes else DEFAULT_SCHEMES
        )
        self.ports: frozenset[int] = frozenset(
            entries.ports if entries.ports else DEFAULT_PORTS.values()
        )


class ScopeRegistry:
    """Session-global target allowlist (arch §6.3).

    Pure and synchronous: ``check`` performs no I/O and never raises on
    untrusted input — every malformed URL becomes a denial. The registry
    knows nothing about agents, tools, or the event bus (it is wired into
    the invariant layer and the HTTP client by the engine).
    """

    __slots__ = ("_compiled", "_entries", "_out_of_scope")

    def __init__(self, entries: ScopeEntries | None = None) -> None:
        """Build the registry from the config ``scope`` section.

        An empty/omitted allowlist denies every host — fail-closed by
        construction (arch §6.3; the session is unusable against a target
        that was never allowlisted).
        """
        self._entries: ScopeEntries = entries if entries is not None else ScopeEntries()
        self._compiled = _CompiledScope(self._entries)
        self._out_of_scope: dict[tuple[str, str, str], OutOfScopeEndpoint] = {}

    # ---- checks (called before every network hop, arch §6.2) ----

    def check(self, url: str) -> ScopeVerdict:
        """Decide whether ``url`` may be contacted (arch §6.3).

        Evaluation order is fixed for deterministic reasons: parse →
        scheme → host (IP subnets, then domains) → port. The first failure
        becomes the verdict.

        Args:
            url: the candidate URL (untrusted, LLM-authored).

        Returns:
            :meth:`ScopeVerdict.allow` when every rule passes, otherwise a
            denial carrying the agent-facing reason.
        """
        try:
            parts = urlsplit(url.strip())
            hostname = parts.hostname
            if not parts.scheme or hostname is None:
                return ScopeVerdict.deny(
                    ScopeDenialKind.PARSE, f"not a usable absolute URL: {url!r}"
                )
            scheme = parts.scheme.lower()
            if scheme not in self._compiled.schemes:
                return ScopeVerdict.deny(
                    ScopeDenialKind.SCHEME,
                    f"scheme {scheme!r} is not allowlisted "
                    f"(allowed: {sorted(self._compiled.schemes)})",
                )
            explicit_port = parts.port  # raises ValueError for garbage ports
            port = explicit_port if explicit_port is not None else DEFAULT_PORTS.get(scheme)
            if port is None:
                return ScopeVerdict.deny(
                    ScopeDenialKind.PORT,
                    f"no explicit port and no default for scheme {scheme!r}",
                )
            host_reason = self._host_denial_reason(hostname)
            if host_reason is not None:
                return ScopeVerdict.deny(ScopeDenialKind.HOST, host_reason)
            if port not in self._compiled.ports:
                return ScopeVerdict.deny(
                    ScopeDenialKind.PORT,
                    f"port {port} is not allowlisted (allowed: {sorted(self._compiled.ports)})",
                )
            return ScopeVerdict.allow()
        except ValueError as error:  # urlsplit/port parse failures
            return ScopeVerdict.deny(
                ScopeDenialKind.PARSE, f"unparseable URL {url!r}: {error}"
            )

    def _host_denial_reason(self, hostname: str) -> str | None:
        """Denial reason for the host part, or ``None`` when it is allowed."""
        if hostname and self._host_allowed(hostname):
            return None
        return (
            f"host {hostname!r} is outside the scope allowlist "
            f"(domains: {list(self._compiled.domains)}, "
            f"subnets: {[str(net) for net in self._compiled.networks]})"
        )

    def _host_allowed(self, hostname: str) -> bool:
        """Domain/subdomain or IP-subnet membership of one hostname."""
        candidate = _normalized_domain(hostname)
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            address = None
        if address is not None:
            return any(address in network for network in self._compiled.networks)
        return any(
            candidate == domain or candidate.endswith(f".{domain}")
            for domain in self._compiled.domains
        )

    def out_of_scope_reason(
        self, url: str, method: str | None = None
    ) -> str | None:
        """Denial reason when ``url`` hits an endpoint marked out-of-scope.

        Implements the ``invariant: out-of-scope-target`` rule (arch §6.3):
        memory ``Endpoint`` records flagged ``out_of_scope=True`` are never
        served by the network tools. A URL may pass the domain allowlist
        (e.g. the operator excluded one path of an allowed host) and still
        be denied here.

        Args:
            url: the candidate URL (untrusted).
            method: the HTTP method of the call; ``None`` (method unknown)
                matches *any* marked record on the host+path — fail-closed.

        Returns:
            The denial reason, or ``None`` when no marked record matches.
        """
        try:
            parts = urlsplit(url.strip())
            hostname = parts.hostname
            if hostname is None:
                return None  # not a URL: scope parsing already denies it
            explicit_port = parts.port
            port = (
                explicit_port
                if explicit_port is not None
                else DEFAULT_PORTS.get(parts.scheme.lower())
            )
            if port is None:
                return None  # port rules belong to the scope check
            host_port = _host_port_of(hostname, port)
            bare_host = _normalized_domain(hostname)
            path = _normalized_path(parts.path)
            wanted = method.strip().upper() if method else None
            for (record_host, record_method, record_path), _record in self._out_of_scope.items():
                if record_host not in (host_port, bare_host) or record_path != path:
                    continue
                if wanted is None or record_method in ("*", wanted):
                    return (
                        f"endpoint {record_method} {host_port}{path} is a marked "
                        f"out-of-scope target; requests to out-of-scope endpoints are "
                        f"never served (invariant: out-of-scope-target, arch §6.3)"
                    )
            return None
        except ValueError:
            return None  # unparseable: the scope check denies it separately

    def marked_endpoints(self) -> tuple[OutOfScopeEndpoint, ...]:
        """All marked out-of-scope endpoint records (diagnostics/tests)."""
        return tuple(self._out_of_scope.values())

    # ---- mutations ----

    def extend(self, entries: ScopeEntries, origin: str) -> None:
        """Merge new entries into the allowlist (arch §6.3).

        Only an operator decision may widen the scope: ``origin`` must be
        the exact string ``"operator"`` (the memory ``ScopeEntry.origin``
        vocabulary). Any other caller — a module tool, an agent, platform
        code without an operator decision — is rejected and *nothing* is
        merged. The ``ScopeChanged`` journal event is published by the HITL
        contour (P3.3), not here.

        Raises:
            ScopeExtensionDenied: when ``origin != "operator"``.
        """
        if origin != "operator":
            msg = (
                f"scope extension denied: origin must be 'operator' (operator decision "
                f"only, arch §6.3), got {origin!r}; no entries were merged"
            )
            raise ScopeExtensionDenied(msg)
        merged = ScopeEntries(
            domains=list(dict.fromkeys([*self._entries.domains, *entries.domains])),
            ip_subnets=list(dict.fromkeys([*self._entries.ip_subnets, *entries.ip_subnets])),
            ports=list(dict.fromkeys([*self._entries.ports, *entries.ports])),
            schemes=list(dict.fromkeys([*self._entries.schemes, *entries.schemes])),
        )
        self._entries = merged
        self._compiled = _CompiledScope(merged)

    def mark_out_of_scope(self, endpoints: Sequence[OutOfScopeEndpoint]) -> None:
        """Record endpoints that network tools must never serve (arch §6.3).

        The platform contour passes memory ``Endpoint`` records flagged
        ``out_of_scope=True``. Idempotent; duplicates collapse. Unlike
        :meth:`extend` no origin gate is needed: marking only *shrinks*
        what the swarm may touch (fail-closed direction).

        A record ``host`` without an explicit port matches the endpoint on
        *any* port (records are expected to carry the full ``host:port``,
        arch §4.2 — the portless form is the lenient fallback).

        Args:
            endpoints: the records to mark (``host`` = full ``host:port``).
        """
        for endpoint in endpoints:
            bare_host, port = _split_record_host(endpoint.host)
            host_key = f"{bare_host}:{port}" if port is not None else bare_host
            record = OutOfScopeEndpoint(
                host=host_key, method=endpoint.method, path=_normalized_path(endpoint.path)
            )
            self._out_of_scope[(record.host, record.method, record.path)] = record

    @property
    def entries(self) -> ScopeEntries:
        """Snapshot of the current allowlist (wiring/diagnostics)."""
        return self._entries


__all__ = [
    "DEFAULT_PORTS",
    "DEFAULT_SCHEMES",
    "OutOfScopeEndpoint",
    "ScopeDenialKind",
    "ScopeEntries",
    "ScopeExtensionDenied",
    "ScopeRegistry",
    "ScopeVerdict",
]
