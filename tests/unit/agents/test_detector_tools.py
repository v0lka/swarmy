"""xss-detector tool + module-guardrail tests (T5.2.1/T5.2.2, spec §8.3).

Tool behaviors are pinned on synthetic bodies; the two ``guardrails.yaml``
rules are loaded from the real installed module folder and evaluated with
the pipeline's own :func:`evaluate_rule` — the exact semantics the runtime
enforces (regex *search* over argument values, conjunction of predicates).
"""

from __future__ import annotations

import json
from importlib import resources
from typing import TYPE_CHECKING

import pytest
from tests.helpers.module_tools import load_tool_file

from swarmy.guardrails.dsl import parse_module_guardrails
from swarmy.guardrails.pipeline import _CompiledRule, evaluate_rule

if TYPE_CHECKING:
    from swarmy.guardrails.models import ModuleGuardrails

pytestmark = pytest.mark.unit

#: The detector tool modules, imported loader-style (dash-named folder is
#: not an importable package — arch §8.3 mechanics).
marker = load_tool_file("xss-detector", "marker")
reflection = load_tool_file("xss-detector", "reflection")

#: Forbidden constructs no safe payload may carry (the module's own mandate).
_DANGEROUS = ("<script", "javascript:", "onerror", "onload", "alert(", "eval(")


def _module_guardrails(name: str) -> ModuleGuardrails:
    """Parse the real guardrails.yaml of one built-in module."""
    text = (
        resources.files("swarmy.agents").joinpath(f"{name}/guardrails.yaml").read_text(
            encoding="utf-8"
        )
    )
    return parse_module_guardrails(text, source=f"{name}/guardrails.yaml")


def _denies(
    guardrails: ModuleGuardrails, rule_id: str, tool: str, args: dict[str, object]
) -> bool:
    """Whether ``rule_id`` denies this call under the pipeline semantics."""
    rule = next(r for r in guardrails.rules if r.id == rule_id)
    return evaluate_rule(_CompiledRule.compile(rule), tool, args)


def _of(json_text: str) -> dict[str, object]:
    """Decode a tool result (tests only)."""
    return json.loads(json_text)


class TestMarkers:
    """make_marker + build_probe_url."""

    def test_marker_shape_and_uniqueness(self) -> None:
        """Default prefix swx + 16 hex chars; two calls never collide."""
        first, second = marker.make_marker(), marker.make_marker()
        assert first.startswith("swx")
        assert len(first) == len("swx") + 16
        assert first != second

    def test_marker_prefix_sanitized(self) -> None:
        """A hostile prefix cannot smuggle payload syntax into the token."""
        assert marker.make_marker(prefix="<script>").startswith("script")

    def test_probe_url_appends_replaces_and_preserves(self) -> None:
        """Append on a bare URL; replace in place; keep other params/fragment."""
        base = "http://127.0.0.1:1/query"
        assert marker.build_probe_url(base, "q", "m1") == f"{base}?q=m1"
        assert (
            marker.build_probe_url(f"{base}?page=2&q=orig#frag", "q", "m1")
            == f"{base}?page=2&q=m1#frag"
        )

    def test_probe_url_passthrough_on_junk(self) -> None:
        """Invalid URLs and empty parameter names return the input unchanged."""
        assert marker.build_probe_url("not-a-url", "q", "m1") == "not-a-url"
        assert marker.build_probe_url("http://h/p", "", "m1") == "http://h/p"


class TestPayloadPlans:
    """plan_payloads: safe context-breakers only."""

    def test_every_documented_context_yields_payloads_with_marker(self) -> None:
        """All six contexts produce payloads embedding the marker."""
        for context in (
            "html_text",
            "inside_tag",
            "attribute_value",
            "script_code",
            "comment",
            "unknown",
        ):
            plan = _of(marker.plan_payloads("m1", context))
            assert plan["context"] == context
            payloads = plan["payloads"]
            assert isinstance(payloads, list)
            assert payloads
            assert all("m1" in payload for payload in payloads)

    def test_payloads_stay_inert(self) -> None:
        """No payload contains an executing construct (module mandate)."""
        for context in ("html_text", "inside_tag", "attribute_value", "script_code", "comment"):
            plan = _of(marker.plan_payloads("m1", context))
            for payload in plan["payloads"]:
                lowered = payload.lower()
                for construct in _DANGEROUS:
                    assert construct not in lowered, f"{context}: {payload}"

    def test_unknown_context_errors_with_known_list(self) -> None:
        """A typo'd context returns no payloads and names the valid ones."""
        plan = _of(marker.plan_payloads("m1", "nope"))
        assert plan["payloads"] == []
        assert "html_text" in str(plan["rationale"])


class TestReflectionAnalysis:
    """analyze_reflection contexts."""

    def test_no_reflection_is_no_candidate(self) -> None:
        """An absent marker reports not-reflected with explicit guidance."""
        report = _of(reflection.analyze_reflection("<p>nothing here</p>", "swxm1", "q"))
        assert report["reflected"] is False
        assert report["occurrences"] == []
        assert "no candidate" in report["verdict"]

    def test_html_text_context(self) -> None:
        """A marker in element content classifies as html_text."""
        body = "<html><p>echo swxm1 tail</p></html>"
        report = _of(reflection.analyze_reflection(body, "swxm1", "q"))
        assert report["reflected"] is True
        assert report["contexts"] == ["html_text"]
        assert report["occurrences"][0]["context"] == "html_text"

    def test_attribute_value_context(self) -> None:
        """A marker inside a quoted attribute classifies as attribute_value."""
        body = '<a href="/x?y=swxm1">link</a>'
        report = _of(reflection.analyze_reflection(body, "swxm1", "y"))
        assert report["contexts"] == ["attribute_value"]

    def test_script_code_context(self) -> None:
        """A marker inside a script block classifies as script_code."""
        body = "<script>var x = 'swxm1';</script>"
        report = _of(reflection.analyze_reflection(body, "swxm1", "q"))
        assert report["contexts"] == ["script_code"]

    def test_comment_context(self) -> None:
        """A marker inside an HTML comment classifies as comment."""
        body = "<!-- echo: swxm1 -->"
        report = _of(reflection.analyze_reflection(body, "swxm1", "q"))
        assert report["contexts"] == ["comment"]

    def test_occurrence_offsets_and_counts(self) -> None:
        """Offsets point at each occurrence; counts are exact."""
        body = "a swxm1 b swxm1 c"
        report = _of(reflection.analyze_reflection(body, "swxm1", "q"))
        assert report["occurrences"][0]["offset"] == 2
        assert report["occurrences"][1]["offset"] == 10
        assert len(report["occurrences"]) == 2

    def test_contexts_on_mixed_markup(self) -> None:
        """Every context class is assigned on one page, in document order (#61)."""
        marker = "swxm1"
        segments: list[tuple[str, str | None]] = [
            ("<html><p>plain ", "html_text"),
            ("</p><!-- note ", "comment"),
            (" --><script>var a='", "script_code"),
            ("';</script><div class=\"b ", "attribute_value"),
            ("\"><span data-x=1 ", "inside_tag"),
            (">tail ", "html_text"),
            ("</span></div></html>", None),
        ]
        parts: list[str] = []
        expected: list[tuple[int, str]] = []
        offset = 0
        for text, context in segments:
            parts.append(text)
            offset += len(text)
            if context is not None:
                # The marker lands at the end of the segment: inside the
                # markup context this segment's text opened.
                parts.append(marker)
                expected.append((offset, context))
                offset += len(marker)
        report = _of(reflection.analyze_reflection("".join(parts), marker, "q"))
        assert report["reflected"] is True
        got = [(occ["offset"], occ["context"]) for occ in report["occurrences"]]
        assert got == expected
        assert report["contexts"] == [
            "html_text",
            "comment",
            "script_code",
            "attribute_value",
            "inside_tag",
        ]

    def test_later_tag_takes_over_between_occurrences(self) -> None:
        """A '<' between two occurrences governs the later one (from-0 semantics)."""
        body = '<div a="1" swxm1 <span b=2 swxm1 >'
        report = _of(reflection.analyze_reflection(body, "swxm1", "q"))
        got = [occ["context"] for occ in report["occurrences"]]
        # First: the div head carries '=' and '"' → attribute_value.
        # Second: the later '<span' (head without quotes) takes over → inside_tag.
        assert got == ["attribute_value", "inside_tag"]

    def test_marker_saturated_body_classifies_every_occurrence(self) -> None:
        """Occurrences below the cap are all classified, in order (linear scan, #61)."""
        marker = "swxm1"
        body = (
            "<script>"
            + (marker + " ") * 100
            + "</script><div data-x=\""
            + (marker + " ") * 100
            + "\">tail "
            + (marker + " ") * 50
        )
        report = _of(reflection.analyze_reflection(body, marker, "q"))
        assert report["reflected"] is True
        assert report["contexts"] == ["script_code", "attribute_value", "html_text"]
        occurrences = report["occurrences"]
        assert len(occurrences) == 250
        assert report["truncated"] is False
        assert report["total_occurrences"] == 250
        offsets = [occ["offset"] for occ in occurrences]
        assert offsets == sorted(offsets)
        assert occurrences[0]["context"] == "script_code"
        assert occurrences[100]["context"] == "attribute_value"
        assert occurrences[249]["context"] == "html_text"

    def test_degenerate_short_marker_cap(self) -> None:
        """A saturated body keeps the first 500 hits and reports the full count.

        A degenerate short marker would otherwise push an unbounded list
        into the model context — the report caps ``occurrences`` while
        ``total_occurrences``/``truncated``/``verdict`` stay honest.
        """
        marker = "x"
        body = "<script>" + (marker + " ") * 4500 + "</script>"
        report = _of(reflection.analyze_reflection(body, marker, "q"))
        assert report["reflected"] is True
        assert len(report["occurrences"]) == 500
        assert report["truncated"] is True
        assert report["total_occurrences"] == 4500
        assert report["contexts"] == ["script_code"]  # the kept prefix is script-only
        assert "4500" in report["verdict"]
        assert "first 500 kept" in report["verdict"]

    def test_safe_payload_report_survival(self) -> None:
        """Verbatim survival flips the finding signal."""
        body = "prefix <swxtagswxm1> suffix"
        hit = _of(reflection.safe_payload_report(body, "<swxtagswxm1>"))
        assert hit["survived_verbatim"] is True
        miss = _of(reflection.safe_payload_report(body, "&lt;swxtag"))
        assert miss["survived_verbatim"] is False


class TestDetectorGuardrails:
    """AC T5.2.1: TRUE-payloads and dangerous constructs are blocked."""

    def test_true_constructions_blocked(self) -> None:
        """SQLi-style TRUE probes are denied on GET and POST params."""
        guardrails = _module_guardrails("xss-detector")
        blocked_args: dict[str, object] = {
            "url": "http://127.0.0.1:1/query",
            "query": {"q": "1=1"},
        }
        assert _denies(guardrails, "no-true-constructions", "http_get", blocked_args)
        post_args: dict[str, object] = {
            "url": "http://127.0.0.1:1/form",
            "body": "name=x' OR 'x'='x",
        }
        assert _denies(guardrails, "no-true-constructions", "http_post", post_args)

    def test_dangerous_payloads_blocked(self) -> None:
        """Script tags, handlers and alert calls are denied."""
        guardrails = _module_guardrails("xss-detector")
        for payload in (
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(2)>",
            'javascript:alert(3)',
            "eval(atob('x'))",
        ):
            args: dict[str, object] = {
                "url": "http://127.0.0.1:1/query",
                "query": {"q": payload},
            }
            assert _denies(
                guardrails, "no-executing-payloads", "http_get", args
            ), payload

    def test_safe_marker_probe_allowed(self) -> None:
        """The module's own inert payloads pass the guardrails."""
        guardrails = _module_guardrails("xss-detector")
        args: dict[str, object] = {
            "url": "http://127.0.0.1:1/query",
            "query": {"q": "swxm1"},
        }
        for rule in guardrails.rules:
            assert not evaluate_rule(_CompiledRule.compile(rule), "http_get", args)

    def test_crawler_depth_rule_blocks_deep_urls(self) -> None:
        """AC T5.1.1: the crawler depth rule fires at 6+ path segments."""
        guardrails = _module_guardrails("crawler")
        rule = next(r for r in guardrails.rules if r.id == "max-crawl-depth")
        compiled = _CompiledRule.compile(rule)
        deep: dict[str, object] = {"url": "http://h/a/b/c/d/e/f"}
        shallow: dict[str, object] = {"url": "http://h/a/b/c/d"}
        assert evaluate_rule(compiled, "http_get", deep)
        assert not evaluate_rule(compiled, "http_get", shallow)
        # applies_to limits the rule to http_get.
        assert not evaluate_rule(compiled, "http_post", deep)
        # Query strings are not path segments.
        query_heavy: dict[str, object] = {"url": "http://h/a?x=1&y=2&z=3"}
        assert not evaluate_rule(compiled, "http_get", query_heavy)
