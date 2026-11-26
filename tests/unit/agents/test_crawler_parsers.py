"""Crawler parser tool tests (roadmap T5.1.1/T5.1.2, arch §8.7).

Each parser is a pure function: text in, JSON string out. The tests pin the
exact extraction/normalization behaviors the AGENT.md prompt documents.
"""

from __future__ import annotations

import json

import pytest

from swarmy.agents.crawler.tools.parsers import (
    extract_forms,
    extract_links,
    parse_robots_txt,
    parse_sitemap_xml,
)

pytestmark = pytest.mark.unit


def _of(json_text: str) -> dict[str, object]:
    """Decode a parser result (tests only)."""
    return json.loads(json_text)


class TestParseRobotsTxt:
    """robots.txt → disallow/allow/sitemap lists."""

    def test_groups_merged_and_comments_ignored(self) -> None:
        """All user-agent groups merge; comments and empty values skipped."""
        body = (
            "# comment\n"
            "User-agent: *\n"
            "Disallow: /private\n"
            "Disallow:\n"
            "Allow: /public\n"
            "\n"
            "User-agent: badbot\n"
            "Disallow: /secret\n"
        )
        report = _of(parse_robots_txt(body, "http://127.0.0.1:1/robots.txt"))
        assert report["disallowed"] == ["/private", "/secret"]
        assert report["allowed"] == ["/public"]
        assert report["sitemaps"] == []
        assert report["error"] == ""

    def test_sitemaps_resolved_absolute(self) -> None:
        """Relative Sitemap entries resolve against the fetched URL."""
        report = _of(
            parse_robots_txt(
                "Sitemap: /sitemap.xml\nSitemap: http://cdn.example.com/s.xml\n",
                "http://127.0.0.1:1/robots.txt",
            )
        )
        assert report["sitemaps"] == [
            "http://127.0.0.1:1/sitemap.xml",
            "http://cdn.example.com/s.xml",
        ]

    def test_invalid_base_url_reported(self) -> None:
        """A non-absolute base URL yields the error shape."""
        report = _of(parse_robots_txt("Disallow: /x\n", "not-a-url"))
        assert report["error"] != ""
        assert report["disallowed"] == []


class TestParseSitemapXml:
    """sitemap/sitemapindex → absolute URL list."""

    def test_urlset_with_relative_locs(self) -> None:
        """loc entries join the base URL; document order kept; dedup."""
        body = (
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<url><loc>/echo</loc></url>"
            "<url><loc>/query</loc></url>"
            "<url><loc>/echo</loc></url>"
            "</urlset>"
        )
        report = _of(parse_sitemap_xml(body, "http://127.0.0.1:1/sitemap.xml"))
        assert report["urls"] == [
            "http://127.0.0.1:1/echo",
            "http://127.0.0.1:1/query",
        ]
        assert report["count"] == 2

    def test_sitemapindex_locs_collected(self) -> None:
        """sitemapindex documents flow through the same loc collection."""
        body = (
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<sitemap><loc>http://other.example.com/s2.xml</loc></sitemap>"
            "</sitemapindex>"
        )
        report = _of(parse_sitemap_xml(body, "http://127.0.0.1:1/sitemap.xml"))
        assert report["urls"] == ["http://other.example.com/s2.xml"]

    def test_broken_xml_reported(self) -> None:
        """Unparseable XML yields the error shape, not an exception."""
        report = _of(parse_sitemap_xml("<not-xml", "http://127.0.0.1:1/s"))
        assert report["error"] != ""


class TestExtractLinks:
    """HTML → absolute navigation links."""

    def test_resolution_kinds(self) -> None:
        """Absolute, root-relative, directory-relative and ../ refs join."""
        html = (
            '<a href="http://other.example.com/a">x</a>'
            '<a href="/root">r</a>'
            '<a href="sub/page">s</a>'
            '<a href="../up">u</a>'
        )
        report = _of(extract_links(html, "http://127.0.0.1:1/dir/page"))
        assert report["links"] == [
            "http://other.example.com/a",
            "http://127.0.0.1:1/root",
            "http://127.0.0.1:1/dir/sub/page",
            "http://127.0.0.1:1/up",
        ]
        assert report["count"] == 4

    def test_fragments_stripped_and_non_http_skipped(self) -> None:
        """#fragment-only and mailto/javascript refs are counted as skipped."""
        html = (
            '<a href="#top">t</a>'
            '<a href="mailto:x@example.com">m</a>'
            '<a href="javascript:void(0)">j</a>'
            '<a href="/real#frag">r</a>'
        )
        report = _of(extract_links(html, "http://127.0.0.1:1/"))
        assert report["links"] == ["http://127.0.0.1:1/real"]
        assert report["skipped"] == 3

    def test_iframe_src_kept_assets_skipped(self) -> None:
        """iframe src is an endpoint; img/script/link/source are assets."""
        html = (
            '<iframe src="/frame"></iframe>'
            '<img src="/logo.png">'
            '<script src="/app.js"></script>'
            '<link href="/style.css">'
        )
        report = _of(extract_links(html, "http://127.0.0.1:1/"))
        assert report["links"] == ["http://127.0.0.1:1/frame"]


class TestExtractForms:
    """HTML forms → action/method/inputs with locations."""

    def test_get_form_defaults(self) -> None:
        """Default method GET → inputs located in the query."""
        html = '<form action="/search"><input name="q"><input name="page" type="number"></form>'
        report = _of(extract_forms(html, "http://127.0.0.1:1/index"))
        assert report["count"] == 1
        form = report["forms"][0]
        assert form["action"] == "http://127.0.0.1:1/search"
        assert form["method"] == "GET"
        assert form["inputs"] == [
            {"name": "q", "type": "text", "location": "query"},
            {"name": "page", "type": "number", "location": "query"},
        ]

    def test_post_form_body_locations_and_actionless(self) -> None:
        """POST → body locations; empty action resolves to the page URL."""
        html = (
            '<form method="post">'
            '<input name="user" type="text">'
            '<input name="pwd" type="password">'
            '<input type="submit" value="go">'
            "</form>"
        )
        report = _of(extract_forms(html, "http://127.0.0.1:1/login"))
        form = report["forms"][0]
        assert form["action"] == "http://127.0.0.1:1/login"
        assert form["method"] == "POST"
        assert form["inputs"] == [
            {"name": "user", "type": "text", "location": "body"},
            {"name": "pwd", "type": "password", "location": "body"},
        ]

    def test_select_and_textarea_named(self) -> None:
        """Named select/textarea controls become inputs too."""
        html = (
            '<form action="/f"><select name="cat"><option>1</option></select>'
            "<textarea name='msg'></textarea></form>"
        )
        report = _of(extract_forms(html, "http://127.0.0.1:1/"))
        names = [item["name"] for item in report["forms"][0]["inputs"]]
        assert names == ["cat", "msg"]

    def test_unnamed_controls_skipped(self) -> None:
        """Inputs without a name are not recorded."""
        html = '<form action="/f"><input type="text"><input name="ok"></form>'
        report = _of(extract_forms(html, "http://127.0.0.1:1/"))
        assert [item["name"] for item in report["forms"][0]["inputs"]] == ["ok"]


class TestErrorReportsAndUrlResolution:
    """Documented error reports and RFC 3986 query-only refs (#13/#48/#56)."""

    def test_extract_links_invalid_base_url_returns_error_report(self) -> None:
        """A relative base_url yields the structured error, not a raise (#13)."""
        report = _of(extract_links('<a href="/x">x</a>', "not-a-absolute-url"))
        assert report["error"] != ""
        assert report["links"] == []
        assert report["count"] == 0
        assert set(report) == {"links", "count", "skipped", "error"}

    def test_extract_links_error_shape_matches_siblings(self) -> None:
        """The model carries the documented ``error`` field like the others."""
        report = _of(extract_links("<not-parseable", "http://127.0.0.1:1/"))
        assert "error" in report

    def test_query_only_reference_resolves_on_the_page_path(self) -> None:
        """``?page=2`` stays on the fetched page, not its directory (#48)."""
        report = _of(extract_links('<a href="?page=2">next</a>', "http://127.0.0.1:1/a/b.html"))
        assert report["links"] == ["http://127.0.0.1:1/a/b.html?page=2"]

    def test_query_only_reference_replaces_the_base_query(self) -> None:
        """RFC 3986 §5.3: the reference query replaces the base's own query."""
        report = _of(
            extract_links('<a href="?page=2">next</a>', "http://127.0.0.1:1/a/b.html?old=1")
        )
        assert report["links"] == ["http://127.0.0.1:1/a/b.html?page=2"]

    def test_sitemap_rejects_entity_expansion_documents(self) -> None:
        """DOCTYPE/ENTITY declarations are rejected before parsing (#56)."""
        body = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE urlset [<!ENTITY laugh "ha">]>'
            "<urlset><url><loc>/echo&amp;laugh;</loc></url></urlset>"
        )
        report = _of(parse_sitemap_xml(body, "http://127.0.0.1:1/sitemap.xml"))
        assert report["error"] != ""
        assert report["urls"] == []

    def test_sitemap_rejects_any_doctype(self) -> None:
        """Even an entity-free DOCTYPE is rejected (real sitemaps never carry one)."""
        body = "<!DOCTYPE urlset><urlset><url><loc>/x</loc></url></urlset>"
        report = _of(parse_sitemap_xml(body, "http://127.0.0.1:1/sitemap.xml"))
        assert report["error"] != ""
        assert report["urls"] == []
