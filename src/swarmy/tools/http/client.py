"""``SwarmyHttpClient`` — the single network path of a session (arch §6.2, T2.2.2).

Every network call of the session goes through :meth:`SwarmyHttpClient.request`,
which runs the canonical pipeline of arch §6.2 **in order**:

1. **GuardrailPipeline pre-check** (synchronous ``evaluate``) — a deny
   publishes the ``GuardrailBlocked`` journal event through the injected
   wiring (journal-first, arch §5.3) and raises :class:`GuardrailBlocked`
   *before any connection is opened*;
2. ``ResourceLimiter.acquire(host, method)`` — budget/refusal of the limiter
   becomes ``invariant: budget`` (the spent budget is additionally denied by
   the layer-1 invariants before the client is even reached);
3. ``httpx.AsyncClient`` with ``follow_redirects=False`` — **redirects are
   executed manually**: every hop re-runs the scope check (allowlist +
   marked out-of-scope targets) and acquires the limiter again, with a
   depth counter bounded by ``max_redirect_depth``; a cross-domain redirect
   leaving the allowlist is a ``GuardrailBlocked`` (invariant scope);
4. ``EvidenceRecorder`` (when ``spec.evidence``) — raw request/response
   bytes into ``evidence/<request_id>/``, ``Evidence`` pointer row;
5. ``ContextProjector`` — the agent receives only the sanitized
   ``body_preview`` (never the raw body, D21);
6. the :class:`ResponseRecord` carries the redirect chain, the evidence id
   and the ``request_id`` (uuid4 correlation string).

Timeouts come from the limiter's ``connect_timeout_s``/``read_timeout_s``;
a surfacing ``httpx.TimeoutException`` publishes ``GuardrailBlocked(layer=
"invariant", rule_id="timeout")`` through the wiring and returns a textual
feedback to the agent — the raw exception never reaches the model.

Outbound hygiene (arch §6.2, spec §7.1): before the first byte is sent, the
request headers/body are scanned for operator secret values (injected via
the :class:`SecretValues` protocol — ``SecretsConfig.secret_values()`` at
wiring time). A hit publishes a non-blocking warn event and the secret is
masked in the body preview; the call itself proceeds — the operator passed
the credential deliberately, and a warn must never gate it (no LLM in the
deny path, arch §16.5).

Injection (arch §2.5): the client imports only guardrails *models*/invariant
ids, events *models* and its ``tools`` siblings — the session machinery
(journal, bus, memory store) arrives through the typed protocols
:class:`HttpClientEvents` and :class:`EvidenceSink`, so ``tools.*`` never
imports ``swarmy.core`` and the wiring stays swappable in tests.
"""

from __future__ import annotations

import json
import uuid
from time import monotonic
from typing import TYPE_CHECKING, Final, Protocol

import httpx
from pydantic import BaseModel, ConfigDict

from swarmy.events.models import GuardrailBlockedPayload
from swarmy.guardrails.models import (
    BlockedFeedback,
    GuardrailBlocked,
    Verdict,
    feedback_text,
)
from swarmy.tools.http.models import RequestSpec, ResponseRecord
from swarmy.tools.limits import BUDGET_RULE_ID, BudgetExhausted
from swarmy.tools.projector import mask_reference

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from swarmy.guardrails.pipeline import GuardrailPipeline
    from swarmy.memory.models import Evidence
    from swarmy.tools.limits import ResourceLimiter
    from swarmy.tools.projector import ContextProjector
    from swarmy.tools.scope import ScopeRegistry

#: Digest cap of the RD-4 placeholder — kept in parity with
#: ``GuardrailPipeline``'s digest; T2.3.2 replaces both with the projector.
_DIGEST_LIMIT: Final[int] = 512

#: Rule ids of the client-enforced invariants (arch §6.2/§6.3/§6.4 prose and
#: ``BUDGET_RULE_ID`` convention: ``invariant: <name>``, spaced). The layer-1
#: invariant *slots* of ``guardrails.invariants`` keep their own unprefixed
#: spacing; the client's ids surface on redirect hops and timeouts, where the
#: pipeline is not re-evaluated.
SCOPE_RULE_ID: Final[str] = "invariant: scope"
OUT_OF_SCOPE_TARGET_RULE_ID: Final[str] = "invariant: out-of-scope-target"
LIMITS_RULE_ID: Final[str] = "invariant: limits"
TIMEOUT_RULE_ID: Final[str] = "invariant: timeout"

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


def _args_digest(args: Mapping[str, object]) -> str:
    """Sanitized arguments digest of a blocked call (RD-4 placeholder).

    Deterministic JSON serialization (stringified leaves, sorted keys)
    truncated to :data:`_DIGEST_LIMIT` — kept in exact parity with
    :func:`swarmy.guardrails.pipeline.tool_args_digest`; T2.3.2 replaces
    both with the ContextProjector digest.
    """
    raw = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
    if len(raw) <= _DIGEST_LIMIT:
        return raw
    return f"{raw[:_DIGEST_LIMIT]} [truncated {len(raw) - _DIGEST_LIMIT} bytes; full projector digest: T2.3.2]"


class OutboundSecretWarn(BaseModel):
    """Payload of the non-blocking outbound-secret warn event (arch §6.2).

    Published when an operator secret value is detected in the outgoing
    headers/body. The warn never blocks (the operator passed the credential
    deliberately); the journal docking of this platform event type is wired
    by the session contour through :class:`HttpClientEvents`.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    request_id: str
    secret_names: list[str]
    locations: list[str]  # e.g. "header:authorization", "body"


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
        "_limiter",
        "_pipeline",
        "_projector",
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
        self._client: httpx.AsyncClient | None = None

    async def aclose(self) -> None:
        """Close the underlying httpx client (session shutdown / tests)."""
        if self._client is not None:
            client, self._client = self._client, None
            await client.aclose()

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
        digest = _args_digest(args)

        # (a) GuardrailPipeline pre-check — strictly before anything touches
        # the network (arch §6.2 order: guardrails → limiter → httpx).
        result = self._pipeline.evaluate(name, args)
        if result.verdict is Verdict.BLOCK and result.feedback is not None:
            raise await self._publish_blocked(result.feedback, name, digest)

        # Outbound hygiene (non-blocking): detect operator secrets before
        # the first byte is sent; warn + mask in the preview, never gate.
        secret_hits = self._detect_outbound(spec.headers, spec.body)
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

            request = self._build_request(method, url, spec.headers, spec.query, body)
            if not request_head:
                request_head = _request_head_bytes(request)
            try:
                async with self._limiter.acquire(url.host or "", method):
                    # (b) limiter slot held for the whole hop; redirects are
                    # disabled at the httpx level — the manual loop below
                    # owns every hop (each hop re-acquires its own slot).
                    response = await self._http_client().send(request, stream=True)
                    content, truncated = await self._read_capped(response)
            except httpx.TimeoutException as error:
                return await self._timeout_feedback(name, digest, str(url), error)
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
                redirects.append(str(next_url))
                method, body = _hop_method(method, response.status_code, body)
                url = next_url
                depth += 1
                continue
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
    ) -> httpx.Request:
        """Build the httpx request of one hop (query merged into the URL)."""
        return httpx.Request(method, url, params=dict(query), headers=dict(headers), content=body)

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
        self, headers: Mapping[str, str], body: str | None
    ) -> list[tuple[str, str, str]]:
        """Secret values found in the outgoing headers/body (arch §6.2).

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

    async def _timeout_feedback(
        self, tool_name: str, digest: str, url: str, error: httpx.TimeoutException
    ) -> str:
        """Journal the ``invariant: timeout`` event and return the feedback text.

        The timeout violation is a guardrail outcome (arch §6.2): the event
        is published exactly like a deny, but the agent receives a *returned*
        textual feedback instead of an exception — the call produced no
        response, so there is nothing to render.
        """
        limits = self._limiter.limits
        feedback = BlockedFeedback(
            rule_id=TIMEOUT_RULE_ID,
            layer="invariant",
            reason=(
                f"the request to {url} exceeded the session timeout budget "
                f"(connect {limits.connect_timeout_s}s / read {limits.read_timeout_s}s): "
                f"{type(error).__name__}; no response was received"
            ),
        )
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
    "EvidenceSink",
    "HttpClientEvents",
    "OutboundSecretWarn",
    "SecretValues",
    "SwarmyHttpClient",
]
