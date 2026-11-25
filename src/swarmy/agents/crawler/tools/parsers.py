"""Parser tools of the built-in ``crawler`` module (arch §8.7, roadmap T5.1.1).

Pure, deterministic text-to-structure converters for passive reconnaissance:
the LLM fetches raw content through the platform ``http_get`` tool and feeds
the bodies here; the JSON results feed ``memory_upsert_endpoint``. No tool
in this file performs I/O — network stays on the platform client, storage
stays on the platform memory tools (arch §8.5). Every parser is inert
(``swarmy_risk_class = "passive"``, AD-7) and therefore never gated by HITL
profiles.

Stdlib parsing only: ``html.parser`` for markup, ``xml.etree.ElementTree``
for sitemaps. ``urllib`` is deliberately not used (forbidden import for
module tools, arch §8.5) — the tiny URL-join helper below covers the
relative-reference resolution the crawler needs.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Final
from xml.etree import ElementTree

from pydantic import BaseModel, ConfigDict

from swarmy.guardrails.models import RiskClass

_SCHEME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_ASSET_TAGS: Final[frozenset[str]] = frozenset({"img", "script", "link", "source"})
_SKIPPED_REF_PREFIXES: Final[tuple[str, ...]] = (
    "mailto:",
    "tel:",
    "javascript:",
    "data:",
)


class RobotsReport(BaseModel):
    """Structured view of one robots.txt body (tool result)."""

    model_config = ConfigDict(extra="forbid")

    disallowed: list[str] = []  # Disallow path prefixes (politeness queue filter)
    allowed: list[str] = []  # explicit Allow path prefixes
    sitemaps: list[str] = []  # absolute sitemap URLs to fetch next
    error: str = ""  # non-empty when the body is not parseable


class SitemapReport(BaseModel):
    """Structured view of one sitemap/sitemapindex body (tool result)."""

    model_config = ConfigDict(extra="forbid")

    urls: list[str] = []  # absolute, deduplicated, in document order
    count: int = 0
    error: str = ""


class LinksReport(BaseModel):
    """Absolute in-page links extracted from one HTML body (tool result)."""

    model_config = ConfigDict(extra="forbid")

    links: list[str] = []  # absolute http(s) URLs, deduplicated, in page order
    count: int = 0
    skipped: int = 0  # non-http refs (mailto:, javascript:, fragments, assets)


class FormInput(BaseModel):
    """One named input control of a form (tool result)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    type: str  # declared or default "text"
    location: str  # "query" for GET forms, "body" for POST forms


class FormInfo(BaseModel):
    """One HTML form resolved against its page URL (tool result)."""

    model_config = ConfigDict(extra="forbid")

    action: str  # absolute URL (the page URL when the action is empty)
    method: str  # upper-case GET/POST (HTML default GET)
    inputs: list[FormInput]


class FormsReport(BaseModel):
    """All forms of one HTML page (tool result)."""

    model_config = ConfigDict(extra="forbid")

    forms: list[FormInfo] = []
    count: int = 0
    error: str = ""


def _base_origin(base_url: str) -> str | None:
    """``scheme://authority`` prefix of ``base_url`` (``None`` when invalid)."""
    if not _SCHEME_RE.match(base_url):
        return None
    rest = base_url.split("://", 1)[1]
    authority = rest.split("/", 1)[0]
    if not authority:
        return None
    scheme = base_url.split("://", 1)[0]
    return f"{scheme}://{authority}"


def _base_dir(base_url: str) -> str:
    """Directory prefix of ``base_url`` (everything up to the last ``/``)."""
    if base_url.count("/") <= 2:  # "scheme://authority" — no path segment yet
        return base_url
    return base_url.rsplit("/", 1)[0]


def _join_url(base_url: str, ref: str) -> str | None:
    """Resolve one link/reference against ``base_url`` (RFC-lite, no urllib).

    Handles absolute URLs, scheme-relative ``//host/path``, root-relative
    ``/path``, and plain relative paths with ``./``/``../`` normalization;
    fragments are dropped, queries kept. Returns ``None`` for refs the
    crawler must not follow (non-http schemes, empty results).
    """
    origin = _base_origin(base_url)
    if origin is None:
        return None
    ref = ref.strip()
    if not ref or ref.startswith("#"):
        return None
    lowered = ref.lower()
    if lowered.startswith(_SKIPPED_REF_PREFIXES):
        return None
    if lowered.startswith(("http://", "https://")):
        resolved = ref
    elif ref.startswith("//"):
        resolved = f"{base_url.split('://', 1)[0]}:{ref}"
    elif ref.startswith("/"):
        resolved = f"{origin}{ref}"
    else:
        resolved = _resolve_relative(_base_dir(base_url), ref)
    resolved = resolved.split("#", 1)[0]
    return resolved or None


def _resolve_relative(base_dir: str, ref: str) -> str:
    """Join a plain relative ``ref`` onto ``base_dir`` with ``./``/``../`` applied.

    ``base_dir`` always carries the ``scheme://authority`` prefix; the
    authority (everything before the first ``/`` after ``://``) is never a
    ``..``-pop target and empty segments are not normalized away.
    """
    scheme, _, rest = base_dir.partition("://")
    authority, _, dir_path = rest.partition("/")
    segments: list[str] = [part for part in dir_path.split("/") if part]
    for part in ref.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if segments:
                segments.pop()
            continue
        segments.append(part)
    return f"{scheme}://{authority}/{'/'.join(segments)}"


class _LinkParser(HTMLParser):
    """Collects navigation links (``a``/``area`` href, ``iframe`` src)."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self.links: list[str] = []
        self.skipped = 0
        self._seen: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = "href" if tag in {"a", "area"} else ("src" if tag == "iframe" else None)
        if attr is None:
            return
        value = dict(attrs).get(attr)  # attrs values are str | None
        if not value:
            return
        resolved = _join_url(self._base_url, value)
        if resolved is None or not resolved.lower().startswith(("http://", "https://")):
            self.skipped += 1
            return
        if resolved not in self._seen:
            self._seen.add(resolved)
            self.links.append(resolved)


class _FormParser(HTMLParser):
    """Reconstructs forms (action/method/inputs) of one HTML page."""

    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._page_url = page_url
        self.forms: list[FormInfo] = []
        self._current: tuple[str, str, list[FormInput]] | None = None

    def _input_of(self, tag: str, attrs: dict[str, str]) -> FormInput | None:
        """The named input control of ``tag`` (``None`` for action buttons)."""
        name = attrs.get("name")
        if not name:
            return None
        input_type = attrs.get("type", "text")
        if tag in {"button", "input"} and input_type.lower() in {
            "submit",
            "reset",
            "button",
            "image",
        }:
            return None
        method = self._current[1] if self._current else "GET"
        location = "query" if method == "GET" else "body"
        return FormInput(name=name, type=input_type.lower(), location=location)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = dict(attrs)
        if tag == "form":
            raw_action = mapping.get("action") or ""
            action = _join_url(self._page_url, raw_action) if raw_action else self._page_url
            method = (mapping.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                method = "GET"
            self._current = (action or self._page_url, method, [])
            return
        if self._current is None or tag not in {"input", "select", "textarea", "button"}:
            return
        input_info = self._input_of(tag, {key: value or "" for key, value in mapping.items()})
        if input_info is not None:
            self._current[2].append(input_info)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            action, method, inputs = self._current
            self.forms.append(FormInfo(action=action, method=method, inputs=inputs))
            self._current = None


def _error_report(error: str, model_cls: type[BaseModel]) -> str:
    """Serialize one parser's full model shape with only ``error`` filled."""
    return model_cls(error=error).model_dump_json()


def parse_robots_txt(text: str, base_url: str) -> str:
    """Parse a ``robots.txt`` body into disallowed paths and sitemap URLs.

    Feed the response body of ``GET /robots.txt`` here. The result lists the
    ``Disallow`` prefixes to skip when queueing links (politeness), the
    explicit ``Allow`` prefixes, and every ``Sitemap:`` URL resolved against
    the base URL — queue those sitemaps next. All user-agent groups are
    merged into one list (v0.1 simplification: crawl the intersection).

    Args:
        text: the raw robots.txt body.
        base_url: the absolute URL robots.txt was fetched from (relative
            sitemap entries are resolved against it).

    Returns:
        JSON object ``{disallowed, allowed, sitemaps, error}``; ``error`` is
        non-empty when the base URL is not absolute http(s).
    """
    if _base_origin(base_url) is None:
        return _error_report(f"base_url is not an absolute http(s) URL: {base_url!r}", RobotsReport)
    disallowed: list[str] = []
    allowed: list[str] = []
    sitemaps: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "disallow" and value:
            disallowed.append(value)
        elif field == "allow" and value:
            allowed.append(value)
        elif field == "sitemap" and value:
            resolved = _join_url(base_url, value)
            if resolved is not None and resolved not in sitemaps:
                sitemaps.append(resolved)
    report = RobotsReport(disallowed=disallowed, allowed=allowed, sitemaps=sitemaps)
    return report.model_dump_json()


def parse_sitemap_xml(text: str, base_url: str) -> str:
    """Parse a sitemap or sitemapindex body into an absolute URL list.

    Feed the response body of a sitemap URL here. Both ``<urlset>`` and
    ``<sitemapindex>`` documents are accepted: every ``<loc>`` entry is
    collected, relative entries are resolved against ``base_url``, results
    are deduplicated in document order. Queue one ``http_get`` per URL and
    record each as an endpoint.

    Args:
        text: the raw XML body.
        base_url: the absolute URL the sitemap was fetched from.

    Returns:
        JSON object ``{urls, count, error}``; ``error`` is non-empty for an
        unparseable XML body or an invalid base URL.
    """
    if _base_origin(base_url) is None:
        return _error_report(f"base_url is not an absolute http(s) URL: {base_url!r}", SitemapReport)
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        return _error_report(f"sitemap XML is not parseable: {exc}", SitemapReport)
    urls: list[str] = []
    for element in root.iter():
        if not element.tag.endswith("loc") or element.text is None:
            continue
        resolved = _join_url(base_url, element.text.strip())
        if resolved is not None and resolved not in urls:
            urls.append(resolved)
    report = SitemapReport(urls=urls, count=len(urls))
    return report.model_dump_json()


def extract_links(html: str, base_url: str) -> str:
    """Extract the navigation links of one HTML page as absolute URLs.

    Feed an HTML response body here while crawling. Collects ``<a>``/``<area>``
    ``href`` and ``<iframe>`` ``src`` references (static asset tags — img,
    script, link, source — are deliberately skipped), resolves them against
    ``base_url``, drops fragments and non-http schemes, deduplicates in page
    order. Queue the URLs you have not fetched yet in this session.

    Args:
        html: the raw HTML body of the page.
        base_url: the absolute URL the page was fetched from.

    Returns:
        JSON object ``{links, count, skipped, error}``; ``error`` is
        non-empty when the base URL is not absolute http(s).
    """
    if _base_origin(base_url) is None:
        return _error_report(f"base_url is not an absolute http(s) URL: {base_url!r}", LinksReport)
    parser = _LinkParser(base_url)
    try:
        parser.feed(html)
        parser.close()
    except ValueError as exc:  # malformed charref / encoding edge in html.parser
        return _error_report(f"HTML is not parseable: {exc}", LinksReport)
    report = LinksReport(links=parser.links, count=len(parser.links), skipped=parser.skipped)
    return report.model_dump_json()


def extract_forms(html: str, page_url: str) -> str:
    """Extract the HTML forms of one page with resolved actions and inputs.

    Feed an HTML response body here. Every ``<form>`` becomes one record:
    ``action`` (absolute; the page URL when empty), ``method`` (upper-case,
    HTML default ``GET``) and its named controls (``input``/``select``/
    ``textarea``; submit/reset/image buttons are skipped). Each input's
    ``location`` is ``query`` for GET forms and ``body`` for POST forms —
    pass them to ``memory_upsert_endpoint`` as ``parameters``.

    Args:
        html: the raw HTML body of the page.
        page_url: the absolute URL the page was fetched from (relative
            form actions are resolved against it).

    Returns:
        JSON object ``{forms, count, error}``; each form is
        ``{action, method, inputs: [{name, type, location}]}``. ``error`` is
        non-empty for an unparseable page or an invalid page URL.
    """
    if _base_origin(page_url) is None:
        return _error_report(f"page_url is not an absolute http(s) URL: {page_url!r}", FormsReport)
    parser = _FormParser(page_url)
    try:
        parser.feed(html)
        parser.close()
    except ValueError as exc:
        return _error_report(f"HTML is not parseable: {exc}", FormsReport)
    report = FormsReport(forms=parser.forms, count=len(parser.forms))
    return report.model_dump_json()


# AD-7: every parser is inert text processing — passive, never HITL-gated.
parse_robots_txt.swarmy_risk_class = RiskClass.PASSIVE
parse_sitemap_xml.swarmy_risk_class = RiskClass.PASSIVE
extract_links.swarmy_risk_class = RiskClass.PASSIVE
extract_forms.swarmy_risk_class = RiskClass.PASSIVE

__all__ = [
    "extract_forms",
    "extract_links",
    "parse_robots_txt",
    "parse_sitemap_xml",
]
