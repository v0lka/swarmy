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


class RequestSpec(BaseModel):
    """One outbound HTTP call of the platform client (arch §6.2).

    Secrets are passed **by name** from ``secrets.yaml`` through the session
    wiring — a raw credential must never be typed into tool arguments (arch
    §12.3). The body byte limit is enforced by the limiter side
    (``max_body_bytes``), not by the spec.
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
    "HttpMethod",
    "RequestSpec",
    "ResponseRecord",
]
