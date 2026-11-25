"""``RequestSpec``/``ResponseRecord`` conformance tests (arch §6.2, T2.2.1).

The field sets and defaults are canonical (roadmap AC: "модели
соответствуют arch §6.2"); an out-of-Literal method is a Pydantic
``ValidationError`` — the client boundary makes ``TRACE``/``CONNECT``
unrepresentable before any rule evaluation.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from swarmy.tools.http.models import RequestSpec, ResponseRecord

_SPEC_FIELDS = {"method", "url", "headers", "query", "body", "evidence", "evidence_depth"}
_RECORD_FIELDS = {
    "status",
    "reason",
    "headers",
    "body_preview",
    "body_bytes",
    "elapsed_ms",
    "redirects",
    "evidence_id",
    "request_id",
}


def test_request_spec_fields_match_arch_6_2() -> None:
    """The spec carries exactly the §6.2 fields with the §6.2 defaults."""
    assert set(RequestSpec.model_fields) == _SPEC_FIELDS
    spec = RequestSpec(method="GET", url="http://app.example.com/")
    assert spec.headers == {}
    assert spec.query == {}
    assert spec.body is None
    assert spec.evidence is True
    assert spec.evidence_depth == "request_response"


def test_response_record_fields_match_arch_6_2() -> None:
    """The record carries exactly the §6.2 fields; only evidence_id defaults."""
    assert set(ResponseRecord.model_fields) == _RECORD_FIELDS
    record = ResponseRecord(
        status=200,
        reason="OK",
        headers={"content-type": "text/plain"},
        body_preview="projected",
        body_bytes=9,
        elapsed_ms=12,
        redirects=["http://app.example.com/step2"],
        request_id="corr-1",
    )
    assert record.evidence_id is None
    assert record.headers == {"content-type": "text/plain"}
    assert record.redirects == ["http://app.example.com/step2"]


def test_invalid_method_is_validation_error() -> None:
    """A method outside the six-verb Literal is rejected by the model."""
    with pytest.raises(ValidationError) as excinfo:
        RequestSpec(method="TRACE", url="http://app.example.com/")
    assert "method" in str(excinfo.value)
    with pytest.raises(ValidationError):
        RequestSpec(method="CONNECT", url="http://app.example.com/")
    with pytest.raises(ValidationError):
        RequestSpec(method="BREW", url="http://app.example.com/")


def test_all_six_literal_methods_validate() -> None:
    """GET/HEAD/POST/PUT/PATCH/DELETE are all constructible."""
    for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        spec = RequestSpec(method=method, url="http://app.example.com/")
        assert spec.method == method


def test_invalid_url_is_validation_error() -> None:
    """A relative or garbage URL cannot enter the pipeline."""
    with pytest.raises(ValidationError):
        RequestSpec(method="GET", url="not-a-url")
    with pytest.raises(ValidationError):
        RequestSpec(method="GET", url="/relative/path")


def test_unknown_field_is_rejected() -> None:
    """Strict models: an unknown key is an argument error, not silent data."""
    with pytest.raises(ValidationError):
        RequestSpec.model_validate(
            {"method": "GET", "url": "http://app.example.com/", "timeout": 99}
        )


def test_invalid_evidence_depth_is_validation_error() -> None:
    """The depth Literal has exactly the D20-produced values."""
    with pytest.raises(ValidationError):
        RequestSpec(
            method="GET",
            url="http://app.example.com/",
            evidence_depth="har",  # type: ignore[arg-type]
        )
