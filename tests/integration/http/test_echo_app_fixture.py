"""Echo-app fixture smoke tests — one per arch §15.2 behavior mode (T2.4.1).

Every mode the perimeter scenarios rely on is exercised directly with
``httpx`` (no swarmy client in between): the fixture must be proven good
before the scenarios build on it. The final test proves the T2.4.1
import-absence AC: ``aiohttp`` is a dev-group dependency only, so the
runtime package (``swarmy`` + its CLI entry module ``swarmy.cli``) must be
importable in a fresh interpreter **without** ``aiohttp`` ever appearing in
``sys.modules`` — a subprocess check of the real runtime surface (more
robust than an AST scan: it also catches transitive runtime imports).
"""

from __future__ import annotations

import subprocess
import sys
import time
from typing import TYPE_CHECKING, Final

import httpx

#: The header the ``/header`` reflection endpoint echoes (arch §15.2); kept
#: in parity with ``ECHO_HEADER`` in tests/fixtures/echo_app/app.py.
ECHO_HEADER: Final[str] = "X-Echo-Value"

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    # Type-only: the fixture objects arrive fully built; the echo-app module
    # itself is loaded at runtime by tests/integration/conftest.py.
    from tests.fixtures.echo_app.app import EchoServer

    SpawnServer = Callable[[], Awaitable[EchoServer]]


async def test_servers_bind_free_ports(spawn_echo_server: SpawnServer) -> None:
    """AC (T2.4.1): fixture servers start/stop on OS-assigned ports, no collision."""
    first = await spawn_echo_server()
    second = await spawn_echo_server()
    assert first.port != second.port
    assert first.base_url.startswith("http://127.0.0.1:")
    async with httpx.AsyncClient() as http:
        for server in (first, second):
            response = await http.get(server.url("/"))
            assert response.status_code == 200
            assert response.text.startswith("echo app is up")


async def test_echo_mode_reflects_query_headers_and_body(
    echo_server: EchoServer,
) -> None:
    """Reflection mode: /echo mirrors query, headers and body (detector feed)."""
    async with httpx.AsyncClient() as http:
        response = await http.get(
            echo_server.url("/echo"),
            params={"q": "hello", "id": "7"},
            headers={ECHO_HEADER: "hdr-value"},
        )
    assert response.status_code == 200
    reflected = response.json()
    assert reflected["method"] == "GET"
    assert reflected["query"] == {"q": "hello", "id": "7"}
    reflected_headers = {key.lower(): value for key, value in reflected["headers"].items()}
    assert reflected_headers["x-echo-value"] == "hdr-value"
    async with httpx.AsyncClient() as http:
        response = await http.post(echo_server.url("/echo"), content=b"post-body-42")
    assert response.json()["body"] == "post-body-42"


async def test_query_mode_reflects_parameters(echo_server: EchoServer) -> None:
    """Reflection mode: /query echoes every query parameter as text."""
    async with httpx.AsyncClient() as http:
        response = await http.get(echo_server.url("/query"), params={"user": "admin"})
    assert response.status_code == 200
    assert response.text == "user=admin\n"


async def test_header_mode_reflects_headers(echo_server: EchoServer) -> None:
    """Reflection mode: /header echoes the X-Echo-Value header verbatim."""
    async with httpx.AsyncClient() as http:
        response = await http.get(echo_server.url("/header"), headers={ECHO_HEADER: "tok-123"})
    assert response.status_code == 200
    assert response.text == "tok-123"


async def test_body_mode_echoes_bytes(echo_server: EchoServer) -> None:
    """Reflection mode: /body returns the request bytes unchanged."""
    payload = b"\x01raw-bytes-\xff-42"
    async with httpx.AsyncClient() as http:
        response = await http.post(echo_server.url("/body"), content=payload)
    assert response.status_code == 200
    assert response.content == payload


async def test_redirect_mode_follows_in_scope_chain(echo_server: EchoServer) -> None:
    """Redirect mode (in-scope): /redirect?n=K chains K same-host 302 hops."""
    async with httpx.AsyncClient(follow_redirects=True) as http:
        response = await http.get(echo_server.url("/redirect"), params={"n": 3})
    assert response.status_code == 200
    assert response.text == "landed\n"
    assert response.url.path == "/redirect"
    assert response.history  # httpx did traverse redirect hops
    assert len(response.history) == 3
    # every hop (3 redirects + landing) arrived at this server: in-scope chain
    assert echo_server.log.count == 4


async def test_redirect_mode_reaches_out_of_scope_target(
    echo_server: EchoServer, spawn_echo_server: SpawnServer
) -> None:
    """Redirect mode (out-of-scope): /redirect/out hands off to the second server."""
    second = await spawn_echo_server()
    async with httpx.AsyncClient(follow_redirects=True) as http:
        response = await http.get(
            echo_server.url("/redirect/out"), params={"to": second.url("/landing")}
        )
    assert response.status_code == 200
    assert response.text.startswith("landing page")
    assert response.url == httpx.URL(second.url("/landing"))
    assert echo_server.log.count == 1  # only the 302 hop was served here
    assert second.log.count == 1  # the second server was contacted by httpx


async def test_large_mode_returns_exact_body(echo_server: EchoServer) -> None:
    """Large-body mode: /large?bytes=N answers with exactly N bytes."""
    async with httpx.AsyncClient() as http:
        response = await http.get(echo_server.url("/large"), params={"bytes": 1234})
    assert response.status_code == 200
    assert len(response.content) == 1234
    assert response.content == b"A" * 1234


async def test_slow_mode_delays_the_response(echo_server: EchoServer) -> None:
    """Slow mode: /slow?ms=N sleeps N milliseconds before answering."""
    started = time.monotonic()
    async with httpx.AsyncClient() as http:
        response = await http.get(echo_server.url("/slow"), params={"ms": 120})
    elapsed = time.monotonic() - started
    assert response.status_code == 200
    assert elapsed >= 0.12


async def test_form_mode_parses_urlencoded_fields(echo_server: EchoServer) -> None:
    """Form mode: POST /form echoes the urlencoded fields as JSON."""
    async with httpx.AsyncClient() as http:
        response = await http.post(
            echo_server.url("/form"), data={"user": "alice", "action": "scan"}
        )
    assert response.status_code == 200
    assert response.json() == {"fields": {"user": "alice", "action": "scan"}}


async def test_sitemap_mode_lists_endpoints(echo_server: EchoServer) -> None:
    """Sitemap mode: /sitemap.xml is served as XML listing the endpoints."""
    async with httpx.AsyncClient() as http:
        response = await http.get(echo_server.url("/sitemap.xml"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    assert "<urlset" in response.text
    assert "/redirect/out" in response.text


async def test_robots_mode_disallows_private(echo_server: EchoServer) -> None:
    """robots.txt mode: served as text/plain, disallows /private."""
    async with httpx.AsyncClient() as http:
        response = await http.get(echo_server.url("/robots.txt"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "User-agent: *" in response.text
    assert "Disallow: /private" in response.text


async def test_log_records_unrouted_requests(echo_server: EchoServer) -> None:
    """The server-side log records every arrival, routed or not (404s too)."""
    async with httpx.AsyncClient() as http:
        response = await http.get(echo_server.url("/definitely/not/mapped"))
    assert response.status_code == 404
    assert echo_server.log.count == 1
    assert echo_server.log.entries[0].target == "/definitely/not/mapped"


def test_runtime_never_imports_aiohttp() -> None:
    """AC (T2.4.1): the runtime surface imports without aiohttp (dev-group only).

    Runs a fresh interpreter importing the runtime package **and** its CLI
    entry module (``pyproject.toml`` entry point ``swarmy.cli:main``), then
    fails if ``aiohttp`` ended up in ``sys.modules`` — catching even
    transitive runtime imports an AST scan could miss. The echo app imports
    aiohttp only inside the pytest process (loaded from tests/fixtures by
    the integration conftest), which is exactly why this probe uses a
    subprocess instead of inspecting the current interpreter.
    """
    probe = "import swarmy, swarmy.cli, sys; sys.exit(1 if 'aiohttp' in sys.modules else 0)"
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, (
        "aiohttp leaked into the runtime import surface:\n"
        f"{completed.stderr.decode(errors='replace')}"
    )
