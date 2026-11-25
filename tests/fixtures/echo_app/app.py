"""Echo application — the controlled aiohttp test target (arch §15.2, T2.4.1).

One configurable server whose behavior modes the F2 integration scenarios
need (roadmap T2.4.2): parameter echo/reflection for detectors, redirect
chains inside and outside the session scope, large bodies, slow endpoints
for timeout tests, form handling, sitemap and robots.txt.

The module is loaded by ``tests/integration/conftest.py`` through
``importlib`` from this exact file path (dev-group dependency — ``aiohttp``
never enters the runtime package, T2.4.1 AC), and every server binds to an
OS-assigned free port (``port=0``) so parallel/parametrized runs never
collide.

Every request that reaches the server (routed or not) is appended to a
:class:`RequestLog` by the root middleware — the "the server never saw the
request" assertions of the perimeter scenarios are log-length checks, which
requires recording *before* routing (404s included).
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Final, NamedTuple

from aiohttp import web

if TYPE_CHECKING:
    from aiohttp.typedefs import Handler

#: Loopback host every fixture server binds (CI matrix safe: no DNS needed).
HOST: Final[str] = "127.0.0.1"

#: Default/cap values of the parameterized behavior modes (fail-safe bounds
#: so a malformed fixture call cannot allocate gigabytes or hang a suite).
DEFAULT_LARGE_BYTES: Final[int] = 65_536
MAX_LARGE_BYTES: Final[int] = 10_485_760
DEFAULT_SLOW_MS: Final[int] = 100
MAX_SLOW_MS: Final[int] = 10_000
MAX_REDIRECT_HOPS: Final[int] = 16

#: Header the ``/header`` reflection endpoint echoes back verbatim.
ECHO_HEADER: Final[str] = "X-Echo-Value"

_SITEMAP_XML: Final[str] = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/{base_path}/echo</loc></url>
  <url><loc>/{base_path}/query</loc></url>
  <url><loc>/{base_path}/header</loc></url>
  <url><loc>/{base_path}/body</loc></url>
  <url><loc>/{base_path}/form</loc></url>
  <url><loc>/{base_path}/redirect</loc></url>
  <url><loc>/{base_path}/redirect/out</loc></url>
  <url><loc>/{base_path}/large</loc></url>
  <url><loc>/{base_path}/slow</loc></url>
  <url><loc>/{base_path}/landing</loc></url>
</urlset>
"""

_ROBOTS_TXT: Final[str] = """User-agent: *
Allow: /
Disallow: /private
"""


class ServerRequest(NamedTuple):
    """One server-side observation of an incoming request (T2.4.2 tests).

    ``ts`` is a wall-clock ``time.time()`` stamp taken at handler-entry —
    the value the rate-limit scenario measures inter-request spacing on.
    """

    ts: float
    method: str
    target: str  # path with query string, as received on the request line


class RequestLog:
    """Append-only server-side record of every request that arrived.

    This is the fixture's ground truth about what the target actually saw:
    a zero-length log after a client call proves no bytes reached the
    server (out-of-scope blocks), while its timestamps carry the arrival
    spacing the rate limiter must enforce.
    """

    __slots__ = ("entries",)

    def __init__(self) -> None:
        """Start with an empty log."""
        self.entries: list[ServerRequest] = []

    def record(self, request: web.Request) -> None:
        """Append one observation (called by the logging middleware)."""
        self.entries.append(
            ServerRequest(ts=time.time(), method=request.method, target=request.path_qs)
        )

    @property
    def count(self) -> int:
        """Number of requests the server has seen so far."""
        return len(self.entries)


async def _index(request: web.Request) -> web.Response:
    """``GET /`` — liveness probe of the fixture server."""
    del request
    return web.Response(text="echo app is up\n")


def _query_map(request: web.Request) -> dict[str, str]:
    """Plain ``str → str`` view of the request query (single values)."""
    return dict(request.query.items())


async def _echo(request: web.Request) -> web.Response:
    """``ANY /echo`` — full reflection of query, headers and body (JSON).

    The detector-facing mode: everything the client sent comes back in one
    structured response, including the exact headers and the request body.
    """
    body = (await request.read()).decode("utf-8", errors="replace")
    return web.json_response(
        {
            "method": request.method,
            "path": request.path,
            "query": _query_map(request),
            "headers": dict(request.headers),
            "body": body,
        }
    )


async def _reflect_query(request: web.Request) -> web.Response:
    """``GET /query`` — plain-text reflection of every query parameter."""
    lines = [f"{key}={value}" for key, value in request.query.items()]
    return web.Response(text="\n".join(lines) + "\n")


async def _reflect_header(request: web.Request) -> web.Response:
    """``GET /header`` — echoes the ``X-Echo-Value`` request header back."""
    return web.Response(text=request.headers.get(ECHO_HEADER, "<unset>"))


async def _reflect_body(request: web.Request) -> web.Response:
    """``POST /body`` — echoes the raw request bytes back verbatim."""
    payload = await request.read()
    return web.Response(
        body=payload, content_type=request.content_type or "application/octet-stream"
    )


async def _form(request: web.Request) -> web.Response:
    """``POST /form`` — parses ``application/x-www-form-urlencoded`` fields.

    The form-handling mode: field names/values come back as JSON (file
    uploads render as ``<file>``; v0.1 scenarios only use text fields).
    """
    data = await request.post()
    fields = {key: (value if isinstance(value, str) else "<file>") for key, value in data.items()}
    return web.json_response({"fields": fields})


def _clamped_int(raw: str | None, default: int, cap: int) -> int:
    """Query-parameter integer parse with a hard cap (fixture robustness)."""
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(0, min(value, cap))


async def _redirect_chain(request: web.Request) -> web.Response:
    """``GET /redirect?n=K`` — in-scope chain of K same-host 302 hops.

    Relative ``Location`` targets (the real-world shape); ``n<=0`` lands
    with a 200 whose body names the hop count the client survived.
    """
    hops = _clamped_int(request.query.get("n"), 0, MAX_REDIRECT_HOPS)
    if hops <= 0:
        return web.Response(text="landed\n")
    raise web.HTTPFound(f"/redirect?n={hops - 1}")


async def _redirect_out(request: web.Request) -> web.Response:
    """``GET /redirect/out?to=URL`` — 302 to an absolute out-of-scope URL.

    The out-of-scope-redirect mode: the scenario passes the base URL of the
    second fixture server (a host/port the session scope never allowlists)
    and asserts the perimeter blocks the hop before connecting.
    """
    to = request.query.get("to", "").strip()
    if not to:
        raise web.HTTPBadRequest(text="the 'to' query parameter is required\n")
    raise web.HTTPFound(to)


async def _large(request: web.Request) -> web.Response:
    """``GET /large?bytes=N`` — deterministic body of exactly N bytes."""
    size = _clamped_int(request.query.get("bytes"), DEFAULT_LARGE_BYTES, MAX_LARGE_BYTES)
    size = max(size, 1)
    return web.Response(body=b"A" * size, content_type="application/octet-stream")


async def _slow(request: web.Request) -> web.Response:
    """``GET /slow?ms=N`` — sleeps N milliseconds, then answers 200."""
    delay_s = _clamped_int(request.query.get("ms"), DEFAULT_SLOW_MS, MAX_SLOW_MS) / 1000.0
    await asyncio.sleep(delay_s)
    return web.Response(text=f"awake after {delay_s:.3f}s\n")


async def _landing(request: web.Request) -> web.Response:
    """``GET /landing`` — the target page of out-of-scope redirect tests."""
    del request
    return web.Response(text="landing page of the fixture server\n")


async def _private(request: web.Request) -> web.Response:
    """``GET /private`` — robots-disallowed page (out-of-scope endpoint mode)."""
    del request
    return web.Response(text="private area of the fixture server\n")


async def _sitemap(request: web.Request) -> web.Response:
    """``GET /sitemap.xml`` — endpoint index of this server instance."""
    del request
    return web.Response(text=_SITEMAP_XML, content_type="application/xml")


async def _robots(request: web.Request) -> web.Response:
    """``GET /robots.txt`` — crawler guidance of the fixture."""
    del request
    return web.Response(text=_ROBOTS_TXT, content_type="text/plain")


def create_app(log: RequestLog) -> web.Application:
    """Build the echo application bound to one shared :class:`RequestLog`.

    Args:
        log: the server-side record the logging middleware appends to.

    Returns:
        The aiohttp application (not yet started — see :class:`EchoServer`).
    """

    @web.middleware
    async def _logging_middleware(
        request: web.Request, handler: Handler
    ) -> web.StreamResponse:
        """Record every arrival (routed or not) before the router runs."""
        log.record(request)
        return await handler(request)

    app = web.Application(middlewares=[_logging_middleware])
    app.router.add_get("/", _index)
    app.router.add_route("*", "/echo", _echo)
    app.router.add_route("*", "/query", _reflect_query)
    app.router.add_route("*", "/header", _reflect_header)
    app.router.add_post("/body", _reflect_body)
    app.router.add_post("/form", _form)
    app.router.add_get("/redirect", _redirect_chain)
    app.router.add_get("/redirect/out", _redirect_out)
    app.router.add_get("/large", _large)
    app.router.add_get("/slow", _slow)
    app.router.add_get("/landing", _landing)
    app.router.add_get("/private", _private)
    app.router.add_get("/sitemap.xml", _sitemap)
    app.router.add_get("/robots.txt", _robots)
    return app


class EchoServer:
    """One running echo-app instance bound to a free loopback port.

    ``start()`` binds ``port=0`` and reads the OS-assigned port back from
    the underlying sockets, so pytest fixtures never collide; ``stop()``
    drains aiohttp cleanly (handlers included — the ``/slow`` mode).
    """

    __slots__ = ("_host", "_log", "_runner", "port")

    def __init__(self, *, host: str, port: int, runner: web.AppRunner, log: RequestLog) -> None:
        """Assemble the started-server handle (use :meth:`start`)."""
        self._host = host
        self.port = port
        self._runner = runner
        self._log = log

    @classmethod
    async def start(cls, *, host: str = HOST) -> EchoServer:
        """Start a fresh echo app on a free port of ``host``.

        Args:
            host: loopback address to bind (default ``127.0.0.1``).

        Returns:
            The running server; its ``port``/``base_url`` are ready to use.
        """
        log = RequestLog()
        runner = web.AppRunner(create_app(log))
        await runner.setup()
        site = web.TCPSite(runner, host, 0)  # port 0: the OS assigns a free port
        await site.start()
        return cls(host=host, port=cls._bound_port(runner), runner=runner, log=log)

    @staticmethod
    def _bound_port(runner: web.AppRunner) -> int:
        """Read the actual bound port back from the runner's real sockets."""
        return int(runner.addresses[0][1])

    @property
    def base_url(self) -> str:
        """``http://host:port`` root of this server."""
        return f"http://{self._host}:{self.port}"

    def url(self, path: str) -> str:
        """Absolute URL of ``path`` on this server (path must start with ``/``)."""
        return f"{self.base_url}{path}"

    @property
    def log(self) -> RequestLog:
        """The server-side request log (perimeter-scenario ground truth)."""
        return self._log

    async def stop(self) -> None:
        """Drain and shut the server down (idempotent via aiohttp cleanup)."""
        await self._runner.cleanup()


__all__ = ["ECHO_HEADER", "HOST", "EchoServer", "RequestLog", "ServerRequest", "create_app"]
