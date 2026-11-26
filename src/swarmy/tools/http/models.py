"""HTTP request/response models of the platform client (arch §6.2, T2.2.1).

``RequestSpec`` is the single argument shape of :meth:`SwarmyHttpClient.
request` — every network call of the session enters the pipeline through it;
``ResponseRecord`` is what the agent receives back: structured metadata plus
``body_preview``, the *already sanitized* projection of arch §6.8 (the raw
bytes stay in the evidence files, D21).

The field sets are canonical (arch §6.2): the models carry exactly those
fields — nothing speculative (P4). Validation is strict (``extra="forbid"``):
an unknown key in an LLM-authored call is a fail-fast argument error, and a
method outside the six-verb Literal is a Pydantic ``ValidationError`` (the
engine rules deny ``TRACE``/``CONNECT`` anyway — the type system makes them
unrepresentable at the client boundary).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

#: The six methods the platform client supports (arch §6.2). The four
#: *named* platform tools are GET/POST/PUT/DELETE (arch §6.1); HEAD and
#: PATCH stay client-reachable (redirect hops rewrite to HEAD/GET, module
#: tools may build specs directly).
HttpMethod = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

#: Evidence depth of one call (arch §6.2): only the request side, or the
#: full request/response pair. Other evidence kinds are reserved, not
#: produced (D20).
EvidenceDepth = Literal["request", "request_response"]


class HopRecord(BaseModel):
    """Raw traffic exchanged on one manual redirect hop (arch §6.2, Issue #42).

    Byte-for-byte what the client put on the wire and read back on that hop —
    the request as rewritten by the redirect (``_hop_method``) and the
    response received before the next hop. Recorded under
    ``evidence/<request_id>/hop-<n>/`` so the stored evidence of a redirect
    chain covers every exchanged pair; the response body is already capped by
    the session reader (arch §6.4).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: 1-based hop number (``hop-1`` is the first exchange of the call).
    hop: int = Field(ge=1)
    request_head: bytes
    request_body: bytes
    response_head: bytes
    response_body: bytes
    response_truncated: bool = False
    response_dropped_bytes: int | None = None


class RequestSpec(BaseModel):
    """One outbound HTTP call of the platform client (arch §6.2).

    Secrets are passed **by name** from ``secrets.yaml`` through the session
    wiring — a raw credential must never be typed into tool arguments (arch
    §12.3). The spec itself carries no size field: the *client* denies a
    request body beyond the session ``max_body_bytes`` before the first hop
    (arch invariant 7, Issue #31), and the response side is capped by the
    client's reader at the same threshold.
    """

    model_config = ConfigDict(extra="forbid")

    method: HttpMethod
    url: HttpUrl
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    evidence: bool = True
    evidence_depth: EvidenceDepth = "request_response"


class ResponseRecord(BaseModel):
    """Result of one platform call, as returned to the agent (arch §6.2).

    ``body_preview`` is the sanitized projection (§6.8: byte budget, secret
    masking, untrusted markers, control-char normalization); the complete
    raw traffic lives in the evidence files linked via ``evidence_id``.
    ``request_id`` is the correlation id for ``memory_save_finding`` and the
    journal trail of the call.
    """

    model_config = ConfigDict(extra="forbid")

    status: int
    reason: str
    headers: dict[str, str]
    body_preview: str
    body_bytes: int
    elapsed_ms: int
    redirects: list[str]
    evidence_id: int | None = None
    request_id: str


__all__ = [
    "EvidenceDepth",
    "HopRecord",
    "HttpMethod",
    "RequestSpec",
    "ResponseRecord",
]
