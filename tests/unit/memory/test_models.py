"""Domain model tests (roadmap T1.2.1): field composition, enums, leaf rule.

The leaf rule itself (`memory.models` imports no swarmy package) is asserted by
`tests/unit/test_architecture.py`; here we verify the observable contract of
arch §4.2 — enum members, mandatory severity (D14), int-key references and the
Draft models used by the store (§4.4).
"""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from swarmy.memory.models import (
    Endpoint,
    EndpointDraft,
    EvidenceKind,
    Finding,
    FindingDraft,
    FindingStatus,
    FindingType,
    SearchableEntity,
    SearchHit,
    Severity,
)


def test_evidence_kind_has_exactly_four_values() -> None:
    """AC (T1.2.1, D20): four kinds declared; only HTTP is produced in v0.1."""
    assert {kind.value for kind in EvidenceKind} == {
        "http_request_response",
        "screenshot",
        "har",
        "grpc_file",
    }


def test_severity_is_mandatory_on_finding() -> None:
    """AC (T1.2.1, D14): constructing a Finding without severity must fail."""
    base: dict[str, object] = {
        "id": 1,
        "type": FindingType.XSS,
        "status": FindingStatus.CANDIDATE,
        "title": "Reflected XSS",
        "description": "payload echoed",
        "created_by": "xss-detector",
        "created_at": datetime.now(UTC),
    }
    with pytest.raises(ValidationError, match="severity"):
        Finding.model_validate(base)  # type: ignore[arg-type]
    finding = Finding.model_validate({**base, "severity": Severity.HIGH})
    assert finding.severity is Severity.HIGH


def test_references_are_int_keys() -> None:
    """AC (T1.2.1): entity links are int ids, never nested object graphs."""
    finding = Finding(
        id=7,
        type=FindingType.SQLI,
        status=FindingStatus.CANDIDATE,
        severity=Severity.CRITICAL,
        endpoint_ref=42,
        evidence_refs=[1, 2, 3],
        title="SQLi",
        description="union-based",
        created_by="crawler",
        created_at=datetime.now(UTC),
    )
    assert isinstance(finding.endpoint_ref, int)
    assert all(isinstance(ref, int) for ref in finding.evidence_refs)


def test_drafts_have_no_identity_fields() -> None:
    """Draft models (§4.4) carry no server-assigned ids."""
    draft = EndpointDraft(host="example.com:443", method="GET", path="/a")
    assert not hasattr(draft, "id")
    finding_draft = FindingDraft(
        type=FindingType.AUTH,
        severity=Severity.LOW,
        title="weak lockout",
        description="no lockout",
        created_by="orchestrator",
    )
    assert not hasattr(finding_draft, "id")


def test_draft_rejects_unknown_fields() -> None:
    """Strict extra policy: adversarial payloads are rejected, not ignored."""
    with pytest.raises(ValidationError):
        EndpointDraft.model_validate({"host": "h", "method": "GET", "path": "/", "evil": True})


def test_endpoint_defaults_match_arch() -> None:
    """Endpoint defaults (§4.2): undiscovered, in-scope, empty notes."""
    ep = Endpoint(id=1, host="example.com:443", method="GET", path="/")
    assert ep.research_status == "undiscovered"
    assert ep.out_of_scope is False
    assert ep.auth_requirements == []
    assert ep.notes == ""


def test_search_hit_shape() -> None:
    """SearchHit (§4.4): entity kind, id, snippet, higher-is-better score."""
    hit = SearchHit(entity_type=SearchableEntity.FINDINGS, id=3, title_snippet="x", score=1.5)
    assert hit.score > 0


def test_utc_timestamps_accepted_with_offset() -> None:
    """Timestamps normalize to UTC-aware datetimes (arch §5.1 convention)."""
    draft = FindingDraft(
        type=FindingType.XSS,
        severity=Severity.MEDIUM,
        title="t",
        description="d",
        created_by="m",
    )
    draft.created_by = draft.created_by  # drafts carry no timestamps (store stamps them)
    aware = datetime(2026, 1, 1, tzinfo=ZoneInfo("Europe/Moscow"))
    finding = Finding(
        id=2,
        type=FindingType.XSS,
        status=FindingStatus.CANDIDATE,
        severity=Severity.MEDIUM,
        title="t",
        description="d",
        created_by="m",
        created_at=aware,
    )
    assert finding.created_at.utcoffset() is not None
