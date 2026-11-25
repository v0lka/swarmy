"""``EvidenceRecorder`` tests: raw files + Evidence rows (T2.2.4).

Roadmap AC: evidence files are byte-exact against the traffic up to the
``max_body_bytes`` threshold (beyond it: marker line); the ``Evidence``
record is linked through ``ResponseRecord.evidence_id`` (the id returned by
the real ``MemoryStore`` here); ``evidence_depth="request"`` writes no
``response.txt``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from swarmy.memory.models import EntityType, Evidence, EvidenceKind
from swarmy.tools.http.evidence import PRODUCED_KIND, EvidenceRecorder

if TYPE_CHECKING:
    from pathlib import Path

    from swarmy.core.database import Database
    from swarmy.memory.store import MemoryStore

_REQUEST_HEAD = b"GET /x HTTP/1.1\r\nHost: app.example.com\r\n"
_RESPONSE_HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"


def recorder(tmp_path: Path, store: MemoryStore, max_body_bytes: int) -> EvidenceRecorder:
    """A recorder over the real store with the given body threshold."""
    return EvidenceRecorder(
        evidence_dir=tmp_path / "evidence", store=store, max_body_bytes=max_body_bytes
    )


async def test_files_byte_exact_up_to_threshold(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """Under the threshold the files carry the traffic byte-for-byte."""
    store, _database = store_env
    evidence = await recorder(tmp_path, store, max_body_bytes=1024).record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="corr-1",
        request_id="rid-full",
        include_response=True,
        response_head=_RESPONSE_HEAD,
        response_body=b"hello world",
    )
    unit = tmp_path / "evidence" / "rid-full"
    assert (unit / "request.txt").read_bytes() == _REQUEST_HEAD + b"\r\n"
    assert (unit / "response.txt").read_bytes() == _RESPONSE_HEAD + b"\r\n" + b"hello world"
    assert evidence.session_paths == [
        "evidence/rid-full/request.txt",
        "evidence/rid-full/response.txt",
    ]


async def test_body_beyond_threshold_truncated_with_marker(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """Beyond the threshold: kept prefix byte-exact + §6.8 truncation marker."""
    store, _database = store_env
    evidence = await recorder(tmp_path, store, max_body_bytes=8).record(
        request_head=_REQUEST_HEAD,
        request_body=b"Q" * 20,
        tool="http_post",
        correlation_id="corr-2",
        request_id="rid-capped",
        include_response=True,
        response_head=_RESPONSE_HEAD,
        response_body=b"B" * 20,
    )
    unit = tmp_path / "evidence" / "rid-capped"
    expected_request = _REQUEST_HEAD + b"\r\n" + b"Q" * 8 + b"\n[truncated 12 bytes]\n"
    expected_response = _RESPONSE_HEAD + b"\r\n" + b"B" * 8 + b"\n[truncated 12 bytes]\n"
    assert (unit / "request.txt").read_bytes() == expected_request
    assert (unit / "response.txt").read_bytes() == expected_response
    assert evidence.id


async def test_evidence_record_created_in_memory_and_linked(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """The Evidence row is readable via MemoryStore and carries the metadata."""
    store, _database = store_env
    evidence = await recorder(tmp_path, store, max_body_bytes=1024).record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="corr-3",
        request_id="rid-row",
        include_response=True,
        response_head=_RESPONSE_HEAD,
        response_body=b"ok",
    )
    row = await store.get(EntityType.EVIDENCE, evidence.id)
    assert row.kind is PRODUCED_KIND
    assert row.kind is EvidenceKind.HTTP_REQUEST_RESPONSE  # D20: the only produced kind
    assert row.session_paths == [
        "evidence/rid-row/request.txt",
        "evidence/rid-row/response.txt",
    ]
    assert row.metadata["tool"] == "http_get"
    assert row.metadata["correlation_id"] == "corr-3"
    assert row.metadata["request_id"] == "rid-row"
    assert row.metadata["ts"]  # recorded timestamp
    assert json.loads(json.dumps(row.session_paths)) == row.session_paths
    assert evidence.finding_ref is None  # attached later via save_finding


async def test_depth_request_writes_no_response_txt(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """``evidence_depth="request"``: no response file, one session path."""
    store, _database = store_env
    evidence = await recorder(tmp_path, store, max_body_bytes=1024).record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="corr-4",
        request_id="rid-request-only",
        include_response=False,
        response_head=_RESPONSE_HEAD,
        response_body=b"ignored",
    )
    unit = tmp_path / "evidence" / "rid-request-only"
    assert (unit / "request.txt").is_file()
    assert not (unit / "response.txt").exists()
    assert evidence.session_paths == ["evidence/rid-request-only/request.txt"]


async def test_rows_accumulate_in_the_evidence_table(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """Two calls produce two distinct Evidence rows (ids increment)."""
    store, _database = store_env
    rec = recorder(tmp_path, store, max_body_bytes=1024)
    first = await rec.record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="c",
        request_id="rid-a",
        include_response=True,
        response_head=_RESPONSE_HEAD,
        response_body=b"a",
    )
    second = await rec.record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="c",
        request_id="rid-b",
        include_response=False,
        response_head=_RESPONSE_HEAD,
        response_body=b"b",
    )
    assert isinstance(first, Evidence)
    assert second.id > first.id
    row_b = await store.get(EntityType.EVIDENCE, second.id)
    assert row_b.metadata["request_id"] == "rid-b"


async def test_response_truncation_marker_with_known_dropped_count(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """Reader-cut body: canonical §6.8 marker with the exact dropped count."""
    store, _database = store_env
    await recorder(tmp_path, store, max_body_bytes=16).record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="c",
        request_id="rid-cut-known",
        include_response=True,
        response_head=_RESPONSE_HEAD,
        response_body=b"R" * 16,  # what the client's reader kept
        response_truncated=True,
        response_dropped_bytes=84,  # declared Content-Length 100
    )
    unit = tmp_path / "evidence" / "rid-cut-known"
    expected = _RESPONSE_HEAD + b"\r\n" + b"R" * 16 + b"\n[truncated 84 bytes]\n"
    assert (unit / "response.txt").read_bytes() == expected


async def test_response_truncation_marker_with_unknown_total_size(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """Streaming body without Content-Length: explicit limit marker, no fake N."""
    store, _database = store_env
    await recorder(tmp_path, store, max_body_bytes=16).record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="c",
        request_id="rid-cut-unknown",
        include_response=True,
        response_head=_RESPONSE_HEAD,
        response_body=b"R" * 16,
        response_truncated=True,
        response_dropped_bytes=None,
    )
    unit = tmp_path / "evidence" / "rid-cut-unknown"
    raw = (unit / "response.txt").read_bytes()
    assert raw.startswith(_RESPONSE_HEAD + b"\r\n" + b"R" * 16)
    assert raw.rstrip(b"\n").endswith(b"the remainder was not read]")
    assert b"[truncated " not in raw  # no invented byte count


async def test_no_truncation_marker_without_cutoff(
    tmp_path: Path, store_env: tuple[MemoryStore, Database]
) -> None:
    """A fully read response carries no truncation marker."""
    store, _database = store_env
    await recorder(tmp_path, store, max_body_bytes=16).record(
        request_head=_REQUEST_HEAD,
        request_body=b"",
        tool="http_get",
        correlation_id="c",
        request_id="rid-whole",
        include_response=True,
        response_head=_RESPONSE_HEAD,
        response_body=b"small body",
    )
    unit = tmp_path / "evidence" / "rid-whole"
    raw = (unit / "response.txt").read_bytes()
    assert raw == _RESPONSE_HEAD + b"\r\n" + b"small body"
    assert b"truncated" not in raw
