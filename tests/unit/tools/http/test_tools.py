"""Platform HTTP tools tests: risk classes, ownership, pipeline pass (T2.2.3).

Roadmap AC: risk classes are set per method (AD-7) and visible through the
registry; the tools pass the ``GuardrailPipeline`` — an out-of-scope call is
blocked before the transport is ever reached.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import pytest

from swarmy.guardrails.models import RiskClass
from swarmy.tools.http.tools import register_http_tools
from swarmy.tools.limits import ResourceLimiter
from swarmy.tools.registry import ToolRegistry, ToolRegistryError

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.unit.tools.http.conftest import EventSpy

    from swarmy.tools.http.client import SwarmyHttpClient

    ClientFactory = Callable[..., SwarmyHttpClient]
    TransportFactory = Callable[..., httpx.MockTransport]

_EXPECTED_RISK = {
    "http_get": RiskClass.PASSIVE,
    "http_post": RiskClass.NETWORK_WRITE,
    "http_put": RiskClass.NETWORK_WRITE,
    "http_delete": RiskClass.NETWORK_WRITE,
}


def make_registry(client: SwarmyHttpClient) -> ToolRegistry:
    """Register the platform tools into a fresh registry (helper)."""
    registry = ToolRegistry()
    register_http_tools(registry, client)
    return registry


def test_risk_classes_set_per_method(make_client: ClientFactory, make_transport: TransportFactory) -> None:
    """AD-7: GET is passive, POST/PUT/DELETE are network-write (registry view)."""
    calls: list[httpx.Request] = []
    client = make_client(transport=make_transport({}, calls))
    registry = make_registry(client)
    assert registry.risk_classes() == _EXPECTED_RISK
    for name in _EXPECTED_RISK:
        entry = registry.entry(name)
        assert entry.owner == "platform"
        assert entry.source == "builtin"
    # The AD-7 attribute sits on the tool functions themselves.
    for name, risk_class in _EXPECTED_RISK.items():
        assert registry.entry(name).fn.swarmy_risk_class is risk_class


async def test_out_of_scope_get_returns_feedback_not_exception(
    make_client: ClientFactory,
    make_transport: TransportFactory,
    default_limits: object,
    event_spy: EventSpy,
) -> None:
    """The tools pass the pipeline: out-of-scope calls get feedback, no network."""
    calls: list[httpx.Request] = []
    limiter = ResourceLimiter(default_limits)  # type: ignore[arg-type]
    client = make_client(transport=make_transport({}, calls), limiter_override=limiter)
    registry = make_registry(client)
    tool = registry.entry("http_get").fn
    feedback = await tool(url="http://outside.example.net/")
    assert isinstance(feedback, str)
    assert "invariant guardrail layer" in feedback
    assert "invariant: scope" in feedback
    assert calls == []  # the block happens before any connection
    assert limiter.budget_used == 0  # ...and before the limiter is engaged
    assert event_spy.blocked[0].tool_name == "http_get"


async def test_http_get_returns_json_record(
    make_client: ClientFactory, make_transport: TransportFactory, base_url: str
) -> None:
    """An in-scope GET returns the JSON-serialized ResponseRecord."""
    calls: list[httpx.Request] = []
    transport = make_transport({"/items": httpx.Response(200, text="items-body")}, calls)
    client = make_client(transport=transport)
    registry = make_registry(client)
    tool = registry.entry("http_get").fn
    raw = await tool(url=f"{base_url}/items", query={"page": "1"})
    payload = json.loads(raw)
    assert payload["status"] == 200
    assert payload["request_id"]
    assert payload["evidence_id"] is not None
    assert "items-body" in payload["body_preview"]
    assert [str(call.url) for call in calls] == [f"{base_url}/items?page=1"]


async def test_http_post_body_reaches_transport(
    make_client: ClientFactory, make_transport: TransportFactory, base_url: str
) -> None:
    """POST bodies travel through the client and land in the request."""
    calls: list[httpx.Request] = []
    transport = make_transport({"/form": httpx.Response(201, text="created")}, calls)
    client = make_client(transport=transport)
    registry = make_registry(client)
    tool = registry.entry("http_post").fn
    payload = json.loads(await tool(url=f"{base_url}/form", body="a=1&b=2"))
    assert payload["status"] == 201
    assert calls[0].read() == b"a=1&b=2"
    assert registry.risk_classes()["http_post"] is RiskClass.NETWORK_WRITE


async def test_http_put_and_delete_pass_pipeline(
    make_client: ClientFactory, make_transport: TransportFactory, base_url: str
) -> None:
    """PUT/DELETE wrappers build specs with their fixed methods."""
    calls: list[httpx.Request] = []
    transport = make_transport(
        {"/thing": httpx.Response(200, text="put-ok"), "/thing/42": httpx.Response(204)},
        calls,
    )
    client = make_client(transport=transport)
    registry = make_registry(client)
    put_raw = await registry.entry("http_put").fn(url=f"{base_url}/thing", body="x")
    delete_raw = await registry.entry("http_delete").fn(url=f"{base_url}/thing/42")
    assert json.loads(put_raw)["status"] == 200
    assert json.loads(delete_raw)["status"] == 204
    assert [call.method for call in calls] == ["PUT", "DELETE"]


async def test_duplicate_registration_fails_fast(make_client: ClientFactory, make_transport: TransportFactory) -> None:
    """Registering twice collides — fail-fast, arch §4.5 (session start)."""
    calls: list[httpx.Request] = []
    client = make_client(transport=make_transport({}, calls))
    registry = make_registry(client)
    with pytest.raises(ToolRegistryError) as excinfo:
        register_http_tools(registry, client)
    assert any("duplicate tool name" in problem for problem in excinfo.value.problems)
