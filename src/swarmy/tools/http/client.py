"""``SwarmyHttpClient`` — the single network path of a session (arch §6.2, T2.2.2).

Every network call of the session goes through :meth:`SwarmyHttpClient.request`,
which runs the canonical pipeline of arch §6.2 **in order**:

1. **GuardrailPipeline pre-check** (synchronous ``evaluate``) — a deny
   publishes the ``GuardrailBlocked`` journal event through the injected
   wiring (journal-first, arch §5.3) and raises :class:`GuardrailBlocked`
   *before any connection is opened*;
2. limiter-side request-body cap — a body beyond the session
   ``max_body_bytes`` is denied with ``invariant:limits`` (arch invariant 7:
   the resource discipline also bounds what is *sent*, Issue #31);
3. outbound hygiene scan over headers, body **and** query (warn-not-block);
4. ``ResourceLimiter.acquire(host, method)`` — budget/refusal of the limiter
   becomes ``invariant:budget`` (the spent budget is additionally denied by
   the layer-1 invariants before the client is even reached);
5. ``httpx.AsyncClient`` with ``follow_redirects=False`` — **redirects are
   executed manually**: every hop re-runs the deterministic guardrail
   pipeline against the hop's (method, url) (F-7), the scope check
   (allowlist + marked out-of-scope targets) and acquires the limiter again,
   with a depth counter bounded by ``max_redirect_depth``; a cross-domain
   redirect leaving the allowlist is a ``GuardrailBlocked`` (invariant scope);
   every allowlisted *name* is additionally resolved before the hop (F-11,
   invariant host-pin): all resolved addresses are verified against the
   scope ``ip_subnets``, the first resolution is pinned for the session,
   a broken pin or a hung resolver denies, and the connection targets a
   verified address — the request URL carries the pinned IP while
   ``Host``/SNI/cert verification stay the original name;
6. ``EvidenceRecorder`` (when ``spec.evidence``) — raw request/response
   bytes into ``evidence/<request_id>/`` plus one ``hop-N/`` pair per
   followed hop, so the stored evidence is byte-for-byte the exchanged
   traffic (Issue #42); ``Evidence`` pointer row;
7. ``ContextProjector`` — the agent receives only the sanitized
   ``body_preview`` (never the raw body, D21);
8. the :class:`ResponseRecord` carries the redirect chain, the evidence id
   and the ``request_id`` (uuid4 correlation string).

Timeouts come from the limiter's ``connect_timeout_s``/``read_timeout_s``;
a surfacing ``httpx.TimeoutException`` publishes ``GuardrailBlocked(layer=
"invariant", rule_id="timeout")`` through the wiring and returns a textual
feedback to the agent — the raw exception never reaches the model. Every
other transport failure (``httpx.HTTPError`` that is not a timeout:
ConnectError, ProtocolError, DecodingError, ReadError, ...) takes the same
structured-feedback contour under ``invariant:transport`` (entry #34):
journalled ``GuardrailBlocked`` with the masked args digest and a returned
feedback text — the reason carries only the exception type name, never the
raw exception text.

Outbound hygiene (arch §6.2, spec §7.1): before the first byte is sent, the
request headers, body and query parameters are scanned for operator secret
values (injected via the :class:`SecretValues` protocol —
``SecretsConfig.secret_values()`` at wiring time). A hit publishes a
non-blocking warn event and the secret is masked in the body preview; the
call itself proceeds — the operator passed the credential deliberately, and
a warn must never gate it (no LLM in the deny path, arch §16.5).

Injection (arch §2.5): the client imports only guardrails *models*/invariant
ids, events *models* and its ``tools`` siblings — the session machinery
(journal, bus, memory store) arrives through the typed protocols
:class:`HttpClientEvents` and :class:`EvidenceSink`, so ``tools.*`` never
imports ``swarmy.core`` and the wiring stays swappable in tests.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import uuid
from collections.abc import Mapping
from time import monotonic
from typing import TYPE_CHECKING, Final, Protocol

import httpx

from swarmy.events.models import GuardrailBlockedPayload, OutboundSecretWarnPayload
from swarmy.guardrails.invariants import INVARIANT_PREFIX
from swarmy.guardrails.models import (
    BlockedFeedback,
    GuardrailBlocked,
    Verdict,
    feedback_text,
)
from swarmy.tools.http.models import HopRecord, RequestSpec, ResponseRecord
from swarmy.tools.limits import BUDGET_RULE_ID, BudgetExhausted
from swarmy.tools.projector import mask_reference

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from swarmy.guardrails.pipeline import GuardrailPipeline
    from swarmy.memory.models import Evidence
    from swarmy.tools.limits import ResourceLimiter
    from swarmy.tools.projector import ContextProjector
    from swarmy.tools.scope import ScopeRegistry

#: Masked arguments digest of a blocked call (RD-4 retired, Issue #10 ↔ F-16).
#:
#: The deterministic JSON serialization (stringified leaves, sorted keys) is
#: masked with the client's known operator secret values *and* routed through
#: the injected :class:`ContextProjector` — a superset of the treatment
#: :func:`swarmy.guardrails.pipeline.tool_args_digest` applies (that one
#: relies on the projector's injected rules alone). Every ``GuardrailBlocked``
#: the client journals carries this digest, so a verbatim operator secret can
#: never reach the journal from headers/body/query — independent of how the
#: session projector was wired. Implemented locally (not imported from
#: ``guardrails.pipeline``) to keep the arch §2.5 boundary (``tools.*``
#: imports guardrails *models* only).
def _mask_string_leaves(value: object, secret_values: Mapping[str, str]) -> object:
    """Replace every known secret value inside the string leaves of ``value``."""
    if isinstance(value, str):
        masked = value
        for secret_name, secret_value in secret_values.items():
            if secret_value and secret_value in masked:
                masked = masked.replace(secret_value, mask_reference(secret_name))
        return masked
    if isinstance(value, Mapping):
        return {key: _mask_string_leaves(item, secret_values) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        masked_items = [_mask_string_leaves(item, secret_values) for item in value]
        return type(value)(masked_items)  # type: ignore[return-value, arg-type]
    return value


def _masked_args_digest(
    args: Mapping[str, object],
    projector: ContextProjector,
    secret_values: Mapping[str, str],
) -> str:
    """Build the sanitized digest of one blocked call's arguments."""
    masked = _mask_string_leaves(dict(args), secret_values)
    try:
        raw = json.dumps(masked, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        raw = repr(masked)
    return projector.project(raw)

#: Rule ids of the client-enforced invariants (arch §6.2/§6.3/§6.4): the
#: canonical ``invariant:<name>`` machine spelling (arch §5.1) — exactly the
#: ids the layer-1 invariant slots of ``guardrails.invariants`` produce, so
#: one journal column holds one spelling per semantic rule (Issue #21). The
#: prose wording belongs in ``reason``, never in this field. These ids
#: surface where the *client's own* checks deny first — redirect depth,
#: timeouts, the request-body cap — and on the client-side per-hop
#: scope/marked re-checks; the deterministic pipeline (engine/module rules)
#: is additionally re-evaluated against every hop (F-7).
SCOPE_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}scope"
OUT_OF_SCOPE_TARGET_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}out-of-scope-target"
LIMITS_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}limits"
TIMEOUT_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}timeout"
#: Non-timeout transport failures (entry #34): ConnectError/ProtocolError/
#: DecodingError/ReadError and the rest of ``httpx.HTTPError`` that is not a
#: ``TimeoutException`` take the same structured-feedback contour as
#: timeouts — journalled ``GuardrailBlocked`` with the masked digest and a
#: returned agent-facing feedback text (arch §6.2: a call that produced no
#: response is still a guardrail outcome, never a raw exception).
TRANSPORT_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}transport"
#: DNS-rebinding guard (F-11, CWE-350): a name in the allowlist is resolved
#: before every hop; **every** resolved address is verified against the
#: scope ``ip_subnets``, the first resolution is pinned for the session,
#: and the hop is wired to connect to a verified address (the pinned URL
#: host carries the IP while ``Host``/SNI/cert verification stay the name —
#: httpx's documented ``sni_hostname`` request extension). A later
#: resolution that no longer contains the pinned address denies the hop,
#: and a resolver that hangs denies too (fail closed). Client-local rule
#: id — the check is I/O-bound and therefore lives in the client's
#: pre-connect path, not in the pure synchronous invariant layer.
HOST_PIN_RULE_ID: Final[str] = f"{INVARIANT_PREFIX}host-pin"

#: Upper bound for one hostname resolution of the rebinding guard. A hung
#: resolver denies the hop (fail closed — a timeout must not silently skip
#: the guard on a hop that then proceeds); an *unresolvable* name still
#: lets the hop through: nothing can be contacted anyway, and the connect
#: itself stays under the limiter's connect timeout.
_RESOLVE_TIMEOUT_S: Final[float] = 10.0

#: Platform tool name implied by each client method (pipeline evaluation
#: keys its layer-2/3 rules on these names). HEAD rides the ``http_get``
#: identity (same read risk class) and PATCH rides ``http_post`` (same
#: ``network-write`` risk class): every client self-evaluation name is a
#: *real* platform tool, so the ``platform-http`` invariant stays coherent
#: for direct client calls of all six Literal methods (arch §6.1/§6.2).
_TOOL_OF_METHOD: Final[dict[str, str]] = {
    "GET": "http_get",
    "HEAD": "http_get",
    "POST": "http_post",
    "PUT": "http_put",
    "PATCH": "http_post",
    "DELETE": "http_delete",
}

#: Tool class used for the preview byte budget (arch §6.8 ``context.budgets``).
_PREVIEW_TOOL_CLASS: Final[str] = "http_preview"


def _is_ip_literal(host: str) -> bool:
    """True when ``host`` parses as an IPv4/IPv6 address literal."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class HostResolver(Protocol):
    """Session resolver of the DNS-rebinding guard (F-11, arch §6.2).

    Structural type: production wiring passes
    :class:`GetaddrinfoHostResolver`; tests inject recording fakes. Returns
    the resolution in resolver order (first element = the address the
    connection is expected to target); an empty tuple means "did not
    resolve" (the connect itself will fail — nothing to pin).
    """

    async def resolve(self, host: str) -> tuple[str, ...]:
        """Resolve one hostname to its address literals (order preserved)."""
        ...


class GetaddrinfoHostResolver:
    """Default :class:`HostResolver`: ``loop.getaddrinfo`` (cross-platform).

    The resolution runs off-loop in the default executor (asyncio), so the
    blocking system call never stalls the event loop; POSIX and Windows
    both provide ``getaddrinfo``. Duplicates collapse, order preserved.
    """

    async def resolve(self, host: str) -> tuple[str, ...]:
        """Resolve ``host`` through the running loop's ``getaddrinfo``."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None)
        except (OSError, UnicodeError):
            return ()  # unresolvable: the connect fails on its own
        resolved: list[str] = []
        for family, _type, _proto, _canonname, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = sockaddr[0]
            if not isinstance(address, str) or address in resolved:
                continue
            resolved.append(address)
        return tuple(resolved)


class _HostPin:
    """First-resolution pin per hostname (F-11: rebinding detection).

    The first successful resolution of a hostname is recorded for the
    lifetime of the client (one per session, D19). Every later resolution
    must still contain the pinned address: DNS rebinding swaps the record
    set wholesale, so a vanished pin means the name now answers with a
    different host — the hop is denied. Round-robin/CDN names that keep
    the pinned address among several records stay allowed (multi-record
    rotation is normal; a rebinding replacement is not).
    """

    __slots__ = ("_pins",)

    def __init__(self) -> None:
        """Start with an empty pin table (per-session state)."""
        self._pins: dict[str, str] = {}

    def rebind_reason(self, host: str, resolved: tuple[str, ...]) -> str | None:
        """Pin ``host`` on first sight; denial reason on a broken pin.

        Args:
            host: the lowercase hostname of the URL (already scope-checked).
            resolved: the current resolution (non-empty, resolver order).

        Returns:
            ``None`` when the pin holds (or was just recorded), otherwise
            the agent-facing denial reason.
        """
        pinned = self._pins.get(host)
        if pinned is None:
            self._pins[host] = resolved[0]
            return None
        if pinned in resolved:
            return None
        return (
            f"DNS rebinding guard: {host} resolved to {resolved[0]}"
            + (f" (records: {', '.join(resolved)})" if len(resolved) > 1 else "")
            + f", but the session pinned {pinned} at the first resolution; "
            "the allowlisted name stopped resolving to its pinned address "
            "and the hop was not attempted (invariant: host-pin, arch §6.3)"
        )


#: The warn payload is the *registered* journal taxonomy entry
#: (``OutboundSecretWarnPayload`` in ``events/models.py`` — Issue #29 ↔ F-5):
#: the client keeps its historical name as an alias so the journaled shape
#: can never drift from the decodable registry shape (the events-side tests
#: pin the field parity).
OutboundSecretWarn = OutboundSecretWarnPayload


class SecretValues(Protocol):
    """Structural source of operator secret values (arch §12.3).

    ``SecretsConfig`` satisfies it at wiring time; defining it here keeps
    ``tools.*`` free of ``swarmy.core`` imports (arch §2.5).
    """

    def secret_values(self) -> dict[str, str]:
        """Return the ``name → raw value`` map of the operator secrets."""
        ...


class HttpClientEvents(Protocol):
    """Wiring-provided publisher of the client's platform events.

    Implementations append to the journal *before* any bus fan-out
    (arch §5.3 invariant 2); tests inject recording doubles.
    """

    async def guardrail_blocked(self, payload: GuardrailBlockedPayload) -> None:
        """Publish one ``GuardrailBlocked`` event (invariant denies, timeouts)."""
        ...

    async def outbound_secret_warn(self, payload: OutboundSecretWarn) -> None:
        """Publish the non-blocking outbound-secret warn (arch §6.2)."""
        ...


class EvidenceSink(Protocol):
    """Structural type of the recorder the client writes evidence through.

    :class:`swarmy.tools.http.evidence.EvidenceRecorder` satisfies it; tests
    may inject a spy.
    """

    async def record(
        self,
        *,
        request_head: bytes,
        request_body: bytes,
        tool: str,
        correlation_id: str,
        request_id: str,
        include_response: bool,
        response_head: bytes,
        response_body: bytes,
        response_truncated: bool = False,
        response_dropped_bytes: int | None = None,
        hops: Sequence[HopRecord] = (),
    ) -> Evidence:
        """Persist one evidence unit and return its ``Evidence`` record."""
        ...


def _request_head_bytes(request: httpx.Request) -> bytes:
    """Serialize the wire form of a request head (request line + headers).

    Recorded raw into ``request.txt`` — byte-for-byte what the client put on
    the wire (D21: evidence stays raw, operator secrets included, spec §8.7).
    """
    target = request.url.raw_path.decode("ascii")
    lines = [f"{request.method} {target} HTTP/1.1", *(f"{k}: {v}" for k, v in request.headers.items())]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8", errors="replace")


def _response_head_bytes(response: httpx.Response) -> bytes:
    """Serialize the received response head (status line + headers) raw."""
    # httpx reports the version already prefixed ("HTTP/1.1"); mock/injected
    # responses may carry the bare version — normalize without double prefix.
    version = response.http_version
    prefix = "" if version.upper().startswith("HTTP/") else "HTTP/"
    lines = [
        f"{prefix}{version} {response.status_code} {response.reason_phrase}",
        *(f"{k}: {v}" for k, v in response.headers.items()),
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8", errors="replace")


def _dropped_response_bytes(response: httpx.Response, kept: int) -> int | None:
    """Bytes of the response body the session body limit did not read.

    Exact only when the target declared ``Content-Length``; ``None`` when
    nothing was cut or the total size is unknown (the reader stops at the
    threshold by design — the §6.4 cutoff-at-read, never pull to count).
    """
    declared = _declared_content_length(response)
    if declared is not None and declared > kept:
        return declared - kept
    return None


def _collapsed_headers(response: httpx.Response) -> dict[str, str]:
    """``dict`` view of the response headers; repeated names are comma-joined."""
    headers: dict[str, str] = {}
    for key, value in response.headers.items():
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return headers


def _declared_content_length(response: httpx.Response) -> int | None:
    """``Content-Length`` of the response when present and numeric."""
    declared = response.headers.get("content-length", "")
    return int(declared) if declared.isdigit() else None


def _hop_method(method: str, status: int, body: str | None) -> tuple[str, str | None]:
    """Method/body rewrite of one manual redirect hop (RFC 9110 §7.5 style).

    ``303`` rewrites to ``GET`` (``HEAD`` stays ``HEAD``); the historic
    ``301``/``302`` POST→GET behaviour of every real client is kept;
    ``307``/``308`` preserve method and body.
    """
    if status == 303 and method != "HEAD":
        return "GET", None
    if status in (301, 302) and method == "POST":
        return "GET", None
    return method, body


def _hop_traffic(
    hop: int,
    request: httpx.Request,
    request_body: str | None,
    response: httpx.Response,
    content: bytes,
    truncated: bool,
) -> HopRecord:
    """Raw byte record of one exchanged hop (Issue #42: per-hop evidence).

    The bytes are exactly what the client put on the wire and read back —
    the response body already capped by the session reader.
    """
    return HopRecord(
        hop=hop,
        request_head=_request_head_bytes(request),
        request_body=(request_body or "").encode("utf-8"),
        response_head=_response_head_bytes(response),
        response_body=content,
        response_truncated=truncated,
        response_dropped_bytes=_dropped_response_bytes(response, len(content)),
    )


class SwarmyHttpClient:
    """The guarded HTTP client every session network call goes through.

    One instance per session, shared by all parallel delegations — the
    session-global scope, limiter, guardrail pipeline, projector, secrets,
    evidence recorder and event wiring are injected at construction and the
    client holds no per-agent state (D19: the limiter does not know the
    caller).
    """

    __slots__ = (
        "_client",
        "_correlation",
        "_events",
        "_evidence",
        "_host_pin",
        "_limiter",
        "_pipeline",
        "_projector",
        "_resolver",
        "_scope",
        "_secret_values",
        "_transport",
    )

    def __init__(
        self,
        *,
        scope: ScopeRegistry,
        limiter: ResourceLimiter,
        pipeline: GuardrailPipeline,
        projector: ContextProjector,
        secrets: SecretValues,
        evidence: EvidenceSink,
        events: HttpClientEvents,
        transport: httpx.AsyncBaseTransport | None = None,
        correlation_provider: Callable[[], str] | None = None,
        host_resolver: HostResolver | None = None,
    ) -> None:
        """Inject the session perimeter (arch §6.2).

        Args:
            scope: the session allowlist (checked before every hop).
            limiter: the session-global resource limiter (budget, rate,
                concurrency) and the source of the body/redirect/timeout
                cut-offs.
            pipeline: the guardrail pipeline evaluated before the network.
            projector: the §6.8 sanitizer producing ``body_preview``.
            secrets: operator secrets (``SecretsConfig`` at wiring time) for
                the outbound-hygiene detector.
            evidence: the recorder receiving the raw traffic.
            events: the journal-first publisher of the client's events.
            transport: optional httpx transport override (test seam —
                production wiring passes none).
            correlation_provider: source of the session correlation id
                (delegation context, T3.2.3); defaults to "".
            host_resolver: the DNS-rebinding guard's resolver (F-11); the
                production wiring passes :class:`GetaddrinfoHostResolver`.
                ``None`` disables the guard (injected-transport tests) — the
                pin table is per-client state and every test-built client
                would otherwise pin mock-transport hosts against the real
                resolver.
        """
        self._scope = scope
        self._limiter = limiter
        self._pipeline = pipeline
        self._projector = projector
        self._secret_values: dict[str, str] = dict(secrets.secret_values())
        self._evidence = evidence
        self._events = events
        self._transport = transport
        self._correlation: Callable[[], str] = (
            correlation_provider if correlation_provider is not None else (lambda: "")
        )
        self._resolver = host_resolver
        self._host_pin = _HostPin()
        self._client: httpx.AsyncClient | None = None

    async def aclose(self) -> None:
        """Close the underlying httpx client (session shutdown / tests)."""
        if self._client is not None:
            client, self._client = self._client, None
            await client.aclose()

    async def _resolve_for_hop(
        self, url: httpx.URL
    ) -> tuple[BlockedFeedback | None, tuple[str, ...]]:
        """Verify a name host against the scope subnets and the session pin.

        The pre-connect half of the DNS-rebinding guard (F-11): runs on
        **every** hop (initial request and each manual redirect), after the
        scope allowlist pass. Returns the ``invariant: host-pin`` feedback
        to publish, or ``None`` when the hop may proceed together with the
        verified addresses the connection must target (empty when the hop
        proceeds without an address pin — guard disabled, IP-literal host,
        or an unresolvable name, which cannot be contacted anyway).

        Fail-closed on a hung resolver: a timeout denies the hop — a
        resolution that never returns must not silently skip the guard
        while the hop proceeds. An *unresolvable* name (``OSError`` or an
        empty answer) still proceeds: nothing can be contacted anyway, and
        the connect itself stays under the limiter's connect timeout.
        """
        if self._resolver is None:
            return None, ()  # guard disabled (test seam): no resolution, no pin
        host = url.host
        if not host or _is_ip_literal(host):
            return None, ()  # literal hosts carry no resolution to pin
        try:
            resolved = await asyncio.wait_for(
                self._resolver.resolve(host), timeout=_RESOLVE_TIMEOUT_S
            )
        except TimeoutError:
            return (
                BlockedFeedback(
                    rule_id=HOST_PIN_RULE_ID,
                    layer="invariant",
                    reason=(
                        f"DNS resolution of {host} exceeded "
                        f"{_RESOLVE_TIMEOUT_S:.0f}s: the rebinding guard "
                        "could not verify the address the connection would "
                        "target, so the hop was not attempted "
                        "(invariant: host-pin, arch §6.3)"
                    ),
                ),
                (),
            )
        except (OSError, UnicodeError):
            return None, ()  # unresolvable: the connect fails on its own
        if not resolved:
            return None, ()
        for address in resolved:
            # Every candidate is verified: a mixed record set (a legitimate
            # address smuggled next to an internal one) must not let the
            # connection land on the unverified member.
            subnet_reason = self._scope.resolved_ip_denial_reason(address)
            if subnet_reason is not None:
                return (
                    BlockedFeedback(
                        rule_id=HOST_PIN_RULE_ID,
                        layer="invariant",
                        reason=(
                            f"{host} resolved to {address}, which is outside "
                            f"the session scope: {subnet_reason} The hop was "
                            "not attempted."
                        ),
                    ),
                    (),
                )
        rebind_reason = self._host_pin.rebind_reason(host, resolved)
        if rebind_reason is not None:
            return (
                BlockedFeedback(
                    rule_id=HOST_PIN_RULE_ID, layer="invariant", reason=rebind_reason
                ),
                (),
            )
        return None, resolved

    async def request(self, spec: RequestSpec, *, tool_name: str | None = None) -> ResponseRecord | str:
        """Run one call through the arch §6.2 pipeline, in order.

        Args:
            spec: the request to execute (untrusted, LLM-authored fields).
            tool_name: platform tool name used for pipeline evaluation and
                event payloads; derived from the method when omitted (the
                named wrappers pass their own names).

        Returns:
            The :class:`ResponseRecord` of the final response, or — only for
            a surfacing timeout — the textual agent feedback (the journal
            event is published either way; the raw exception never escapes).

        Raises:
            GuardrailBlocked: when the pipeline, the scope or the limiter
                denies the call (journal event published first); tool
                wrappers catch it and return the feedback text.
        """
        request_id = uuid.uuid4().hex
        name = _TOOL_OF_METHOD[spec.method] if tool_name is None else tool_name
        args: dict[str, object] = {
            "method": spec.method,
            "url": str(spec.url),
            "headers": dict(spec.headers),
            "query": dict(spec.query),
            "body": spec.body,
        }
        # Masked digest (Issue #10 ↔ F-16): every client-published deny and
        # timeout journals this digest, so it masks the client's known secret
        # values explicitly *and* routes through the projector's secret
        # rules — no verbatim secret from headers/body/query can reach the
        # journal, independent of the projector wiring.
        digest = _masked_args_digest(args, self._projector, self._secret_values)

        # (a) GuardrailPipeline pre-check — strictly before anything touches
        # the network (arch §6.2 order: guardrails → limiter → httpx).
        result = self._pipeline.evaluate(name, args)
        if result.verdict is Verdict.BLOCK and result.feedback is not None:
            raise await self._publish_blocked(result.feedback, name, digest)

        # Limiter-side request-body cap (arch invariant 7, Issue #31): the
        # session body threshold denies an oversized LLM-authored body before
        # the first hop — the response read cut-off must not be the only
        # body-size control.
        limits = self._limiter.limits
        body_bytes_len = len(spec.body.encode("utf-8")) if spec.body is not None else 0
        if body_bytes_len > limits.max_body_bytes:
            feedback = BlockedFeedback(
                rule_id=LIMITS_RULE_ID,
                layer="invariant",
                reason=(
                    f"request body of {body_bytes_len} bytes exceeds the session "
                    f"max_body_bytes ({limits.max_body_bytes}); no byte was sent"
                ),
            )
            raise await self._publish_blocked(feedback, name, digest)

        # Outbound hygiene (non-blocking): detect operator secrets before
        # the first byte is sent (headers, body *and* query — every request
        # field is scanned, F-8); warn + mask in the preview, never gate.
        secret_hits = self._detect_outbound(spec.headers, spec.body, spec.query)
        if secret_hits:
            await self._events.outbound_secret_warn(
                OutboundSecretWarn(
                    tool_name=name,
                    request_id=request_id,
                    secret_names=[secret_name for secret_name, _v, _l in secret_hits],
                    locations=[location for _n, _v, location in secret_hits],
                )
            )

        url = httpx.URL(str(spec.url))
        method = spec.method
        body = spec.body
        redirects: list[str] = []
        hops: list[HopRecord] = []
        depth = 0
        request_head: bytes = b""
        started = monotonic()
        content = b""
        truncated = False
        response: httpx.Response | None = None

        while True:
            limits = self._limiter.limits
            if depth > limits.max_redirect_depth:
                feedback = BlockedFeedback(
                    rule_id=LIMITS_RULE_ID,
                    layer="invariant",
                    reason=(
                        f"redirect depth {depth} exceeds the session max_redirect_depth "
                        f"({limits.max_redirect_depth}); the chain was not followed further"
                    ),
                )
                raise await self._publish_blocked(feedback, name, digest)
            verdict = self._scope.check(str(url))
            if not verdict.allowed:
                feedback = BlockedFeedback(
                    rule_id=SCOPE_RULE_ID,
                    layer="invariant",
                    reason=(
                        f"URL {str(url)!r} is outside the session scope allowlist: "
                        f"{verdict.reason} (checked before the network hop)"
                    ),
                )
                raise await self._publish_blocked(feedback, name, digest)
            marked = self._scope.out_of_scope_reason(str(url), method)
            if marked is not None:
                feedback = BlockedFeedback(
                    rule_id=OUT_OF_SCOPE_TARGET_RULE_ID, layer="invariant", reason=marked
                )
                raise await self._publish_blocked(feedback, name, digest)
            # DNS-rebinding guard (F-11, CWE-350): resolve allowlisted *names*
            # before the hop; every resolved address must sit inside the
            # scope ip_subnets and the first resolution must still match the
            # session pin. The hop then connects to a verified address (see
            # the pinned request below). IP-literal hosts need no
            # resolution; an unresolvable name skips the guard — the
            # connect fails on its own and contacts nothing; a resolver
            # that *hangs* denies the hop (fail closed).
            pin_feedback, pinned_ips = await self._resolve_for_hop(url)
            if pin_feedback is not None:
                raise await self._publish_blocked(pin_feedback, name, digest)
            # (a2) Redirect-hop rule re-evaluation (F-7): the engine/module
            # layers judged the *original* (method, url) only, but a
            # target-controlled redirect can rewrite both. Before following
            # the hop, the deterministic pipeline runs again against the
            # hop's (method, url) under the hop's implied tool name —
            # operator rule intent holds on every hop (scope/limits above
            # stay the client-side re-checks).
            #
            # The caller's query applies only to the first hop; hops 1..n
            # follow the target's Location URL verbatim (real-client
            # behaviour) — re-merging ``spec.query`` on every hop would
            # revert the target's rewritten query and loop the chain.
            if depth == 0:
                hop_query: Mapping[str, str] = dict(spec.query)
            else:
                hop_query = dict(url.params)
            hop_name = _TOOL_OF_METHOD[method]
            hop_args: dict[str, object] = {
                "method": method,
                "url": str(url),
                "headers": dict(spec.headers),
                "query": hop_query,
                "body": body,
            }
            hop_result = self._pipeline.evaluate(hop_name, hop_args)
            if hop_result.verdict is Verdict.BLOCK and hop_result.feedback is not None:
                raise await self._publish_blocked(hop_result.feedback, hop_name, digest)

            # (b) Connection pinning (F-11): when the guard verified the
            # name's resolution, every connection attempt targets a
            # verified address — the request URL carries the pinned IP for
            # the socket while ``Host``/SNI/certificate verification stay
            # the original name. A failed *connect* falls through to the
            # next verified address (multi-record names, dual families); a
            # timeout does not — the target stalled, no further attempt is
            # hammered. One limiter slot covers the whole hop regardless of
            # connection attempts.
            # (b2) limiter slot held for the whole hop; redirects are
            # disabled at the httpx level — the manual loop below
            # owns every hop (each hop re-acquires its own slot).
            attempts: tuple[str | None, ...] = pinned_ips or (None,)
            request = self._build_request(
                method, url, spec.headers, hop_query, body, pinned_ip=attempts[0]
            )
            if not request_head:
                request_head = _request_head_bytes(request)
            try:
                async with self._limiter.acquire(url.host or "", method):
                    response = None
                    for attempt_index, pinned_ip in enumerate(attempts):
                        if attempt_index > 0:
                            request = self._build_request(
                                method, url, spec.headers, hop_query, body, pinned_ip=pinned_ip
                            )
                        try:
                            response = await self._http_client().send(request, stream=True)
                        except httpx.ConnectError:
                            if attempt_index + 1 < len(attempts):
                                continue  # next verified address
                            raise
                        content, truncated = await self._read_capped(response)
                        break
                    assert response is not None  # the loop exits via break or raise
            # httpx hierarchy: TimeoutException is an HTTPError subclass
            # (TimeoutException → TransportError → RequestError → HTTPError),
            # so the timeout arm must precede the generic transport arm.
            except httpx.TimeoutException as error:
                return await self._transport_feedback(
                    name, digest, str(url), error, rule_id=TIMEOUT_RULE_ID
                )
            except httpx.HTTPError as error:  # entry #34: every other transport failure
                return await self._transport_feedback(
                    name, digest, str(url), error, rule_id=TRANSPORT_RULE_ID
                )
            except BudgetExhausted as error:
                feedback = BlockedFeedback(rule_id=BUDGET_RULE_ID, layer="invariant", reason=error.reason)
                raise await self._publish_blocked(feedback, name, digest) from None

            if response.is_redirect:
                location = response.headers.get("location", "")
                try:
                    next_url = url.join(location)
                except (ValueError, httpx.InvalidURL):
                    # Target-controlled Location header (untrusted data):
                    # fail the call with feedback, never crash the client.
                    return (
                        f"The call to {url} returned an unparseable redirect location "
                        f"{location!r}; the call was stopped (no further hop attempted)."
                    )
                # (e2) Per-hop raw traffic (Issue #42): the redirecting hop's
                # exchanged bytes are captured before the loop overwrites them.
                hops.append(
                    _hop_traffic(len(hops) + 1, request, body, response, content, truncated)
                )
                redirects.append(str(next_url))
                method, body = _hop_method(method, response.status_code, body)
                url = next_url
                depth += 1
                continue
            # Final hop: its exchanged pair is recorded too, so the stored
            # evidence covers every hop byte-for-byte (Issue #42); the
            # top-level files keep their summary semantics (first request +
            # final response).
            hops.append(_hop_traffic(len(hops) + 1, request, body, response, content, truncated))
            break

        assert response is not None  # the loop only exits via break/raise
        elapsed_ms = int((monotonic() - started) * 1000)

        # (e) Evidence: raw, byte-for-byte traffic into the session folder.
        evidence_id: int | None = None
        if spec.evidence:
            record = await self._evidence.record(
                request_head=request_head,
                request_body=(spec.body or "").encode("utf-8"),
                tool=name,
                correlation_id=self._correlation(),
                request_id=request_id,
                include_response=spec.evidence_depth == "request_response",
                response_head=_response_head_bytes(response),
                response_body=content,
                response_truncated=truncated,
                response_dropped_bytes=_dropped_response_bytes(response, len(content)),
                hops=hops,
            )
            evidence_id = record.id

        # (f) Projection: the agent sees only the sanitized preview (D21).
        declared = _declared_content_length(response)
        note = (
            f"[truncated at the session body limit of "
            f"{self._limiter.limits.max_body_bytes} bytes; full content in evidence]"
            if truncated
            else None
        )
        return ResponseRecord(
            status=response.status_code,
            reason=response.reason_phrase,
            headers=_collapsed_headers(response),
            body_preview=self._preview(content, note, secret_hits),
            body_bytes=declared if declared is not None else len(content),
            elapsed_ms=elapsed_ms,
            redirects=redirects,
            evidence_id=evidence_id,
            request_id=request_id,
        )

    # ---- internals ----

    def _http_client(self) -> httpx.AsyncClient:
        """Lazily build the shared httpx client (redirects stay manual)."""
        if self._client is None:
            limits = self._limiter.limits
            self._client = httpx.AsyncClient(
                follow_redirects=False,  # ← arch §6.2: the manual loop owns hops
                timeout=httpx.Timeout(
                    connect=limits.connect_timeout_s,
                    read=limits.read_timeout_s,
                    write=limits.connect_timeout_s,
                    pool=limits.connect_timeout_s,
                ),
                transport=self._transport,
            )
        return self._client

    def _build_request(
        self,
        method: str,
        url: httpx.URL,
        headers: Mapping[str, str],
        query: Mapping[str, str],
        body: str | None,
        *,
        pinned_ip: str | None = None,
    ) -> httpx.Request:
        """Build the httpx request of one hop (query merged into the URL).

        With ``pinned_ip`` (F-11) the connection targets the verified
        address while the wire form stays the original request: the URL
        host carries the pinned IP for the socket, the ``Host`` header is
        set to the original authority (only when the caller did not supply
        one — an operator-authored ``Host`` header is preserved verbatim)
        and the ``sni_hostname`` request extension keeps SNI and
        certificate verification on the original name (httpx ≥ 0.28
        documented extension; plain-HTTP hops ignore it).
        """
        if pinned_ip is None:
            return httpx.Request(
                method, url, params=dict(query), headers=dict(headers), content=body
            )
        pinned_url = url.copy_with(host=pinned_ip)
        pinned_headers = dict(headers)
        if not any(header_name.lower() == "host" for header_name in pinned_headers):
            pinned_headers["Host"] = url.netloc.decode("ascii")
        return httpx.Request(
            method,
            pinned_url,
            params=dict(query),
            headers=pinned_headers,
            content=body,
            extensions={"sni_hostname": url.host},
        )

    async def _read_capped(self, response: httpx.Response) -> tuple[bytes, bool]:
        """Read the response body up to ``max_body_bytes`` and close the stream.

        Returns:
            ``(content, truncated)`` — the kept bytes and whether the
            session body limit cut the body short.
        """
        limit = self._limiter.limits.max_body_bytes
        content = bytearray()
        truncated = False
        try:
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > limit:
                    content.extend(chunk[: limit - len(content)])
                    truncated = True
                    break
                content.extend(chunk)
        finally:
            await response.aclose()
        return bytes(content), truncated

    def _detect_outbound(
        self,
        headers: Mapping[str, str],
        body: str | None,
        query: Mapping[str, str] | None = None,
    ) -> list[tuple[str, str, str]]:
        """Secret values found in the outgoing headers/body/query (arch §6.2).

        Every request field is scanned (F-8): ``query`` parameters carry
        credentials as readily as headers (``?token=<value>``), and the
        promised hygiene warn must not depend on where the value was pasted.

        Returns:
            ``(name, value, locations)`` per hit; ``value`` is kept so the
            preview masking can replace it.
        """
        hits: list[tuple[str, str, str]] = []
        for secret_name, value in self._secret_values.items():
            locations = [
                f"header:{header_name.lower()}"
                for header_name, header_value in headers.items()
                if value in header_value
            ]
            if body and value in body:
                locations.append("body")
            for param_name, param_value in (query or {}).items():
                if value in param_value or value in param_name:
                    locations.append(f"query:{param_name.lower()}")
            if locations:
                hits.append((secret_name, value, "; ".join(locations)))
        return hits

    def _preview(
        self, content: bytes, truncation_note: str | None, secret_hits: list[tuple[str, str, str]]
    ) -> str:
        """Build the sanitized ``body_preview`` (§6.8 steps, in order).

        Detected operator secrets are masked before projection so the byte
        budget applies to the masked text; the projector then runs its own
        masking/budget/untrusted/normalization steps. ``truncation_note``
        marks a body cut at the session limit by the client's reader.
        """
        text = content.decode("utf-8", errors="replace")
        for secret_name, value, _locations in secret_hits:
            text = text.replace(value, mask_reference(secret_name))
        if truncation_note is not None:
            text = f"{text}\n{truncation_note}"
        return self._projector.project(text, tool_class=_PREVIEW_TOOL_CLASS)

    async def _publish_blocked(
        self, feedback: BlockedFeedback, tool_name: str, digest: str
    ) -> GuardrailBlocked:
        """Publish the ``GuardrailBlocked`` journal event, then build the raise.

        Journal-first (arch §5.3 invariant 2): the wiring sink appends the
        event before any fan-out; the returned exception carries the same
        structured feedback for the agent-facing rendering.
        """
        await self._events.guardrail_blocked(
            GuardrailBlockedPayload(
                tool_name=tool_name,
                rule_id=feedback.rule_id,
                layer=feedback.layer,
                reason=feedback.reason,
                tool_args_digest=digest,
            )
        )
        return GuardrailBlocked(feedback)

    async def _transport_feedback(
        self,
        tool_name: str,
        digest: str,
        url: str,
        error: httpx.HTTPError,
        *,
        rule_id: str,
    ) -> str:
        """Journal the invariant event and return the feedback text.

        One structured-feedback contour for a network exchange that ended
        without a usable response (arch §6.2): timeouts under
        ``invariant:timeout`` (the session timeout budget was exceeded) and
        every other ``httpx.HTTPError`` under ``invariant:transport``
        (entry #34 — ConnectError, ProtocolError, DecodingError, ReadError,
        ...). The event is published exactly like a deny — journalled
        ``GuardrailBlocked`` carrying the projector-masked args digest —
        while the agent receives a *returned* textual feedback instead of
        an exception: only the exception *type* name enters the reason,
        never the raw exception text (it may embed untrusted target data or
        secrets), so there is nothing to render a response from.
        """
        limits = self._limiter.limits
        if rule_id == TIMEOUT_RULE_ID:
            reason = (
                f"the request to {url} exceeded the session timeout budget "
                f"(connect {limits.connect_timeout_s}s / read {limits.read_timeout_s}s): "
                f"{type(error).__name__}; no response was received"
            )
        else:
            reason = (
                f"the request to {url} failed in the transport layer before a "
                f"response was received ({type(error).__name__}); no response "
                "was received and nothing was rendered"
            )
        feedback = BlockedFeedback(rule_id=rule_id, layer="invariant", reason=reason)
        await self._events.guardrail_blocked(
            GuardrailBlockedPayload(
                tool_name=tool_name,
                rule_id=feedback.rule_id,
                layer=feedback.layer,
                reason=feedback.reason,
                tool_args_digest=digest,
            )
        )
        return feedback_text(feedback)


__all__ = [
    "LIMITS_RULE_ID",
    "OUT_OF_SCOPE_TARGET_RULE_ID",
    "SCOPE_RULE_ID",
    "TIMEOUT_RULE_ID",
    "TRANSPORT_RULE_ID",
    "EvidenceSink",
    "HttpClientEvents",
    "OutboundSecretWarn",
    "SecretValues",
    "SwarmyHttpClient",
]
