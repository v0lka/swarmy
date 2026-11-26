"""The four named platform HTTP tools over the real contour (arch §6.1, T2.2.3).

The LLM-facing wrappers are the actual session surface an agent calls: each
tool here runs against the **real** ``SwarmyHttpClient`` (pipeline, journal,
bus, evidence) and the echo app. The F2-relevant behaviors are the wrapper
contract itself — JSON-serialized ``ResponseRecord`` on success, guardrail
feedback *text* (never a raised exception) on a deny or a timeout — plus the
AD-7 declarative risk classes the HITL gates key on.
"""

from __future__ import annotations

import json
from contextlib import aclosing
from typing import TYPE_CHECKING, Final

import pytest

from swarmy.guardrails.invariants import INVARIANT_PREFIX
from swarmy.guardrails.models import RiskClass
from swarmy.tools.http.tools import make_http_tools, register_http_tools
from swarmy.tools.limits import ResourceLimiter, ResourceLimits
from swarmy.tools.registry import (
    PLATFORM_OWNER,
    ToolRegistry,
    ToolRegistryError,
    ToolSpec,
    declared_risk_class,
    risk_class_of,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from swarmy.tools.http.client import SwarmyHttpClient
    from tests.fixtures.echo_app.app import EchoServer

    from ..conftest import SessionEnv

    SpawnServer = Callable[[], Awaitable[EchoServer]]

#: Read timeout for the tool-level timeout scenario (mirrors the client
#: scenarios: a 2s ``/slow`` answer against a 0.3s read budget).
SLOW_TOOL_LIMITS: Final[ResourceLimits] = ResourceLimits(
    rate_limit=5000.0,
    max_concurrent_requests=8,
    max_body_bytes=1024,
    max_redirect_depth=5,
    total_request_budget=100,
    connect_timeout_s=1.0,
    read_timeout_s=0.3,
)


async def test_http_get_returns_response_record_json(
    echo_server: EchoServer, client: SwarmyHttpClient, session_env: SessionEnv
) -> None:
    """``http_get`` success: the agent sees the sanitized ResponseRecord JSON."""
    tools = make_http_tools(client)
    record = json.loads(await tools["http_get"](echo_server.url("/query"), query={"tool": "platform"}))
    assert record["status"] == 200
    assert record["reason"] == "OK"
    assert "tool=platform" in record["body_preview"]
    assert record["redirects"] == []
    assert record["request_id"]
    assert record["evidence_id"] is not None
    assert record["headers"]["content-type"].startswith("text/plain")
    assert await session_env.reader.by_type("GuardrailBlocked") == []


async def test_http_post_round_trips_body(
    echo_server: EchoServer, client: SwarmyHttpClient
) -> None:
    """``http_post`` success: the echo app returns exactly the sent body."""
    tools = make_http_tools(client)
    record = json.loads(
        await tools["http_post"](
            echo_server.url("/body"),
            body="platform post payload",
            headers={"content-type": "text/plain"},
        )
    )
    assert record["status"] == 200
    assert "platform post payload" in record["body_preview"]


async def test_http_put_and_delete_reach_the_target(
    echo_server: EchoServer, client: SwarmyHttpClient
) -> None:
    """``http_put``/``http_delete`` execute with their own tool identities."""
    tools = make_http_tools(client)
    put_record = json.loads(await tools["http_put"](echo_server.url("/echo"), body="put-payload"))
    assert put_record["status"] == 200
    # the /echo JSON arrives wrapped in the §6.8 untrusted-content markers,
    # so the projection is asserted by content, not re-parsed as JSON
    assert "put-payload" in put_record["body_preview"]
    assert '"PUT"' in put_record["body_preview"]
    delete_record = json.loads(
        await tools["http_delete"](echo_server.url("/query"), query={"gone": "yes"})
    )
    assert delete_record["status"] == 200
    assert [entry.method for entry in echo_server.log.entries] == ["PUT", "DELETE"]


async def test_blocked_out_of_scope_call_returns_feedback_text(
    echo_server: EchoServer,
    spawn_echo_server: SpawnServer,
    client: SwarmyHttpClient,
    session_env: SessionEnv,
) -> None:
    """A deny is *returned* as guardrail feedback text, never raised (§8.5)."""
    other = await spawn_echo_server()
    tools = make_http_tools(client)
    feedback = await tools["http_get"](other.url("/landing"))
    assert isinstance(feedback, str)
    assert f"{INVARIANT_PREFIX}scope" in feedback  # pipeline invariant deny
    assert "Adjust your plan" in feedback  # canonical §8.5 wording
    assert other.log.count == 0
    blocked = await session_env.reader.by_type("GuardrailBlocked")
    assert len(blocked) == 1
    assert blocked[0].payload.tool_name == "http_get"


async def test_timeout_tool_call_returns_timeout_feedback(
    echo_server: EchoServer, make_client: Callable[..., SwarmyHttpClient]
) -> None:
    """A surfacing timeout rides the same text-feedback contract."""
    limiter = ResourceLimiter(SLOW_TOOL_LIMITS)
    async with aclosing(make_client(limiter=limiter)) as scoped:
        tools = make_http_tools(scoped)
        feedback = await tools["http_get"](echo_server.url("/slow"), query={"ms": "2000"})
    assert isinstance(feedback, str)
    assert "invariant:timeout" in feedback


def test_http_tools_declare_ad7_risk_classes(client: SwarmyHttpClient) -> None:
    """AD-7: GET is passive; POST/PUT/DELETE declare network-write."""
    tools = make_http_tools(client)
    assert declared_risk_class(tools["http_get"]) == (RiskClass.PASSIVE, None)
    for name in ("http_post", "http_put", "http_delete"):
        assert declared_risk_class(tools[name]) == (RiskClass.NETWORK_WRITE, None)
    assert risk_class_of(tools["http_get"]) == RiskClass.PASSIVE
    assert risk_class_of(tools["http_delete"]) == RiskClass.NETWORK_WRITE


def test_register_http_tools_fills_the_registry(client: SwarmyHttpClient) -> None:
    """``register_http_tools`` lands all four tools under the platform owner."""
    registry = ToolRegistry()
    tools = register_http_tools(registry, client)
    assert set(tools) == {"http_get", "http_post", "http_put", "http_delete"}
    with pytest.raises(ToolRegistryError, match="duplicate tool name"):
        registry.register(
            ToolSpec(
                name="http_get",
                fn=tools["http_get"],
                owner=PLATFORM_OWNER,
                source="builtin",
            )
        )
