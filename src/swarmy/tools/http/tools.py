"""Platform HTTP tools: ``http_get``/``http_post``/``http_put``/``http_delete``.

Thin LLM-facing wrappers over :meth:`SwarmyHttpClient.request` (arch §6.1,
§6.2, T2.2.3): each tool builds a :class:`RequestSpec` with its fixed method
and returns either the JSON-serialized :class:`ResponseRecord` or the
agent-facing guardrail feedback text. The client supports all six methods of
the ``HttpMethod`` Literal; only four *named* platform tools exist (arch
§6.1) — HEAD/PATCH stay reachable through module tools building specs
directly.

Risk classification (AD-7): set declaratively via the ``swarmy_risk_class``
attribute — ``GET`` → ``passive``, ``POST``/``PUT``/``PATCH``/``DELETE`` →
``network-write`` — never inferred from arguments, so the HITL approval
gates stay deterministic (arch §7.2). Registration goes through
:func:`register_http_tools` with ``owner="platform"`` / ``source="builtin"``
(arch §6.1).

Contract of every tool here (mirrors ``tools/platform.py``): fully typed
primitive arguments (G3), non-empty LLM-facing docstrings (G10), JSON-string
results (LLM serialization boundary), guardrail denies returned as feedback
text (spec §8.5) instead of raised.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

from swarmy.guardrails.models import GuardrailBlocked, RiskClass
from swarmy.tools.http.models import EvidenceDepth, RequestSpec, ResponseRecord
from swarmy.tools.registry import BUILTIN_SOURCE, PLATFORM_OWNER, ToolRegistry, ToolSpec

if TYPE_CHECKING:
    from collections.abc import Callable

    from swarmy.tools.http.client import SwarmyHttpClient

#: Risk class per tool name (AD-7 / arch §6.1 table): writes gate, reads not.
_RISK_BY_TOOL: Final[dict[str, RiskClass]] = {
    "http_get": RiskClass.PASSIVE,
    "http_post": RiskClass.NETWORK_WRITE,
    "http_put": RiskClass.NETWORK_WRITE,
    "http_delete": RiskClass.NETWORK_WRITE,
}


async def _run(client: SwarmyHttpClient, spec: RequestSpec, tool_name: str) -> str:
    """Call the client and render the outcome for the agent.

    A :class:`GuardrailBlocked` from the client (a redirect hop or the
    limiter denied after the pipeline allowed) is returned as feedback text,
    never raised into the L0 tool machinery (spec §8.5).
    """
    try:
        outcome: ResponseRecord | str = await client.request(spec, tool_name=tool_name)
    except GuardrailBlocked as blocked:
        return blocked.agent_text
    return outcome if isinstance(outcome, str) else outcome.model_dump_json()


def _spec(
    method: Literal["GET", "POST", "PUT", "DELETE"],
    url: str,
    headers: dict[str, str] | None,
    query: dict[str, str] | None,
    body: str | None,
    evidence: bool,
    evidence_depth: EvidenceDepth,
) -> RequestSpec:
    """Build the validated ``RequestSpec`` of one wrapper (fail-fast args)."""
    return RequestSpec(
        method=method,
        url=url,
        headers=headers if headers is not None else {},
        query=query if query is not None else {},
        body=body,
        evidence=evidence,
        evidence_depth=evidence_depth,
    )


def make_http_tools(client: SwarmyHttpClient) -> dict[str, Callable[..., object]]:
    """Build the four platform HTTP tools bound to ``client`` (arch §6.1).

    Args:
        client: the session's ``SwarmyHttpClient`` (pipeline, limiter, scope,
            projector, secrets, evidence and events are injected there).

    Returns:
        ``name → tool function`` for registration (each function carries the
        AD-7 ``swarmy_risk_class`` attribute).
    """

    async def http_get(
        url: str,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        evidence: bool = True,
        evidence_depth: EvidenceDepth = "request_response",
    ) -> str:
        """Perform an HTTP GET against the target and return the response.

        Args:
            url: absolute URL of the target endpoint; must be inside the
                session scope allowlist — out-of-scope calls are blocked
                before any connection is opened.
            headers: optional request headers; pass operator secrets by
                *name* through the session wiring, never raw values.
            query: optional query parameters merged into the URL.
            evidence: record the raw request/response into the session
                evidence folder (default: yes — keep it on for findings).
            evidence_depth: ``"request_response"`` (default) stores the
                response too; ``"request"`` stores only the request side.

        Returns:
            JSON object string: ``status``, ``reason``, ``headers``,
            ``body_preview`` (sanitized body projection — the raw bytes stay
            in evidence), ``body_bytes``, ``elapsed_ms``, ``redirects``
            (URL chain), ``evidence_id`` (for ``memory_save_finding``) and
            ``request_id`` (correlation id). A blocked call returns the
            guardrail feedback text instead.
        """
        spec = _spec("GET", url, headers, query, None, evidence, evidence_depth)
        return await _run(client, spec, "http_get")

    async def http_post(
        url: str,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        evidence: bool = True,
        evidence_depth: EvidenceDepth = "request_response",
    ) -> str:
        """Perform an HTTP POST against the target and return the response.

        A network-write tool (risk class ``network-write``): depending on
        the session HITL profile it may require operator approval before it
        runs. Probing payloads must stay within the testing mandate; the
        engine rules deny data-destroying payloads outright.

        Args:
            url: absolute URL of the target endpoint; must be inside the
                session scope allowlist.
            body: optional request body (text).
            headers: optional request headers; pass secrets by name.
            query: optional query parameters merged into the URL.
            evidence: record the raw request/response (default: yes).
            evidence_depth: ``"request_response"`` (default) or ``"request"``.

        Returns:
            JSON object string with the same shape as ``http_get``, or the
            guardrail feedback text when the call is blocked.
        """
        spec = _spec("POST", url, headers, query, body, evidence, evidence_depth)
        return await _run(client, spec, "http_post")

    async def http_put(
        url: str,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        evidence: bool = True,
        evidence_depth: EvidenceDepth = "request_response",
    ) -> str:
        """Perform an HTTP PUT against the target and return the response.

        A network-write tool (risk class ``network-write``) — use only for
        authorized verification steps (e.g. uploading a canary file inside
        the testing mandate).

        Args:
            url: absolute URL of the target endpoint; must be inside the
                session scope allowlist.
            body: optional request body (text).
            headers: optional request headers; pass secrets by name.
            query: optional query parameters merged into the URL.
            evidence: record the raw request/response (default: yes).
            evidence_depth: ``"request_response"`` (default) or ``"request"``.

        Returns:
            JSON object string with the same shape as ``http_get``, or the
            guardrail feedback text when the call is blocked.
        """
        spec = _spec("PUT", url, headers, query, body, evidence, evidence_depth)
        return await _run(client, spec, "http_put")

    async def http_delete(
        url: str,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
        evidence: bool = True,
        evidence_depth: EvidenceDepth = "request_response",
    ) -> str:
        """Perform an HTTP DELETE against the target and return the response.

        A network-write tool (risk class ``network-write``) — reserved for
        authorized cleanup/verification inside the testing mandate; the
        guardrail layers still deny destructive payloads and out-of-scope
        targets.

        Args:
            url: absolute URL of the target endpoint; must be inside the
                session scope allowlist.
            headers: optional request headers; pass secrets by name.
            query: optional query parameters merged into the URL.
            evidence: record the raw request/response (default: yes).
            evidence_depth: ``"request_response"`` (default) or ``"request"``.

        Returns:
            JSON object string with the same shape as ``http_get``, or the
            guardrail feedback text when the call is blocked.
        """
        spec = _spec("DELETE", url, headers, query, None, evidence, evidence_depth)
        return await _run(client, spec, "http_delete")

    tools: dict[str, Callable[..., object]] = {
        "http_get": http_get,
        "http_post": http_post,
        "http_put": http_put,
        "http_delete": http_delete,
    }
    for name, risk_class in _RISK_BY_TOOL.items():
        # AD-7: the class is declared on the tool function; the registry
        # reads it via ``declared_risk_class``. The closure functions carry
        # no statically declared attributes, so the annotation is attached
        # dynamically (B010 suppressed: the dynamic attach is the point).
        setattr(tools[name], "swarmy_risk_class", risk_class)  # noqa: B010
    return tools


def register_http_tools(
    registry: ToolRegistry, client: SwarmyHttpClient
) -> dict[str, Callable[..., object]]:
    """Register the four platform HTTP tools in ``registry`` (arch §6.1).

    Args:
        registry: the session tool registry.
        client: the session's ``SwarmyHttpClient``.

    Returns:
        The registered ``name → tool function`` mapping.

    Raises:
        ToolRegistryError: on a name collision (fail-fast at session start,
            arch §4.5).
    """
    tools = make_http_tools(client)
    registry.register_many(
        [
            ToolSpec(name=name, fn=tools[name], owner=PLATFORM_OWNER, source=BUILTIN_SOURCE)
            for name in sorted(tools)
        ]
    )
    return tools


__all__ = [
    "make_http_tools",
    "register_http_tools",
]
