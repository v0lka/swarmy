"""Operator-secrets tests (roadmap T2.3.3, arch §12.3 / AD-5).

Acceptance criteria under test:

* the secrets file gets (and keeps) mode ``600`` — POSIX test, Windows
  limitation skipped and documented;
* a write→load round trip preserves every category and value;
* a ``session.yaml``-style snapshot built from a loaded secrets config
  contains masked references only — no raw value (final session-snapshot
  check lands in T3.1.1);
* a test-session scan finds the raw value only in evidence files.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import pytest

from swarmy.core.config import (
    SECRETS_FILE_MODE,
    SecretCategory,
    SecretsConfig,
    SecretsConfigError,
    load_secrets,
    write_secrets,
)
from swarmy.tools.projector import ContextProjector

if TYPE_CHECKING:
    from pathlib import Path

SECRETS_YAML = """\
auth_headers:
  admin-session: "Basic YWRtaW46c2VjcmV0"
cookies:
  session: "SESS=0123456789abcdef"
tokens:
  api-key: "tok_live_abcdef123456"
"""

POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX 0600 modes are not expressible on Windows (documented T2.3.3 limitation)",
)


def _write_raw_secrets(path: Path) -> None:
    """Create a secrets file from the canonical sample text."""
    path.write_text(SECRETS_YAML, encoding="utf-8")


def test_round_trip_load_preserves_categories(tmp_path: Path) -> None:
    """Loading resolves every category, addressing secrets by name."""
    path = tmp_path / "secrets.yaml"
    _write_raw_secrets(path)
    config = load_secrets(path)
    assert config.secret_value("auth_headers", "admin-session") == "Basic YWRtaW46c2VjcmV0"
    assert config.secret_value(SecretCategory.COOKIES, "session") == "SESS=0123456789abcdef"
    assert config.secret_value("tokens", "api-key") == "tok_live_abcdef123456"


def test_write_then_load_round_trip(tmp_path: Path) -> None:
    """A written file loads back to an equal config."""
    path = tmp_path / "secrets.yaml"
    config = SecretsConfig(
        auth_headers={"h": "Basic abc"},
        cookies={"c": "SESS=1"},
        tokens={"t": "tok_secret"},
    )
    write_secrets(path, config)
    assert load_secrets(path) == config


@POSIX_ONLY
def test_mode_tightened_to_600_on_load(tmp_path: Path) -> None:
    """The loader enforces mode 600 regardless of the file's prior mode."""
    path = tmp_path / "secrets.yaml"
    _write_raw_secrets(path)
    path.chmod(0o644)
    load_secrets(path)
    assert path.stat().st_mode & 0o777 == SECRETS_FILE_MODE


@POSIX_ONLY
def test_write_creates_and_restores_mode_600(tmp_path: Path) -> None:
    """A written file is created 600; rewriting a looser file restores 600."""
    path = tmp_path / "secrets.yaml"
    write_secrets(path, SecretsConfig(tokens={"t": "v"}))
    assert path.stat().st_mode & 0o777 == SECRETS_FILE_MODE
    path.chmod(0o644)
    write_secrets(path, SecretsConfig(tokens={"t": "v2"}))
    assert path.stat().st_mode & 0o777 == SECRETS_FILE_MODE


def test_windows_limitation_documented() -> None:
    """The Windows chmod limitation is spelled out where the mode is enforced."""
    import swarmy.core.config as config_module

    module_doc = config_module.__doc__
    assert module_doc is not None
    assert "Windows" in module_doc
    loader_doc = load_secrets.__doc__
    assert loader_doc is not None
    assert "Windows" in loader_doc


def test_missing_file_fails_fast(tmp_path: Path) -> None:
    """An absent secrets file is a fail-fast session-start problem."""
    with pytest.raises(SecretsConfigError, match="not found"):
        load_secrets(tmp_path / "absent.yaml")


@pytest.mark.parametrize(
    ("content", "match"),
    [
        ("tokens: {unclosed", "not valid YAML"),
        ("42", "top level must be a mapping"),
        ("unknown: {a: b}", "unknown"),
        ("tokens: [a, b]", "tokens"),
        ("tokens:\n  t: \"\"", "non-empty"),
        ("cookies:\n  x: \"1\"\ntokens:\n  x: \"2\"", "duplicate secret name"),
    ],
)
def test_invalid_files_rejected_with_report(
    tmp_path: Path, content: str, match: str
) -> None:
    """Every structural problem surfaces as one aggregated fail-fast error."""
    path = tmp_path / "secrets.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SecretsConfigError, match=match):
        load_secrets(path)


def test_unknown_category_or_name_addressing_fails(tmp_path: Path) -> None:
    """Addressing by name fails loudly on unknown categories and names."""
    path = tmp_path / "secrets.yaml"
    _write_raw_secrets(path)
    config = load_secrets(path)
    with pytest.raises(ValueError, match="unknown secret category"):
        config.secret_value("passwords", "x")
    with pytest.raises(KeyError, match="api-key"):
        config.secret_value("tokens", "nope")


def test_empty_secrets_config_is_valid() -> None:
    """An empty (or absent-section) secrets file yields an empty config."""
    empty = SecretsConfig()
    assert list(empty.iter_secrets()) == []
    assert empty.masked_snapshot() == {}
    assert empty.secret_values() == {}


def test_masked_snapshot_contains_no_raw_values(tmp_path: Path) -> None:
    """A session.yaml-style snapshot built from secrets holds references only."""
    path = tmp_path / "secrets.yaml"
    _write_raw_secrets(path)
    config = load_secrets(path)
    snapshot = {"profile": "normal", "secrets": config.masked_snapshot()}
    blob = json.dumps(snapshot)
    for _category, _name, raw_value in config.iter_secrets():
        assert raw_value not in blob
    assert snapshot["secrets"]["tokens.api-key"] == "<masked:api-key>"
    assert snapshot["secrets"]["cookies.session"] == "<masked:session>"
    assert snapshot["secrets"]["auth_headers.admin-session"] == "<masked:admin-session>"


def test_session_scan_raw_value_only_in_evidence(tmp_path: Path) -> None:
    """Scanning a test session finds the raw value in evidence files only.

    The journal line is the projector output (§6.8 step 2 with values
    injected from this loader via the constructor), the snapshot carries
    masked references — so evidence is the single raw-value location.
    """
    session = tmp_path / "session"
    (session / "evidence").mkdir(parents=True)
    path = tmp_path / "secrets.yaml"
    _write_raw_secrets(path)
    config = load_secrets(path)
    raw_value = config.secret_value("tokens", "api-key")

    (session / "evidence" / "ev-1.txt").write_text(
        f"response body leaked {raw_value}", encoding="utf-8"
    )
    (session / "session-snapshot.json").write_text(
        json.dumps(config.masked_snapshot()), encoding="utf-8"
    )
    projector = ContextProjector(secrets=config.secret_values())
    journal_line = projector.project(f"used token {raw_value} against /api", tool_class="http_preview")
    (session / "journal.txt").write_text(journal_line, encoding="utf-8")

    leaking = [
        item
        for item in session.rglob("*")
        if item.is_file() and raw_value in item.read_text(encoding="utf-8")
    ]
    assert leaking == [session / "evidence" / "ev-1.txt"]
    assert "<masked:api-key>" in journal_line


def test_loaded_values_mask_through_projector(tmp_path: Path) -> None:
    """Every loaded secret value is masked under its own name by the projector."""
    path = tmp_path / "secrets.yaml"
    _write_raw_secrets(path)
    config = load_secrets(path)
    projector = ContextProjector(secrets=config.secret_values(), mark_untrusted=False)
    assert projector.project("token tok_live_abcdef123456") == "token <masked:api-key>"
    assert projector.project("SESS=0123456789abcdef") == "<masked:session>"
    assert projector.project("admin-session") == "admin-session"  # the name is not a secret
    assert projector.project("auth Basic YWRtaW46c2VjcmV0") == "auth <masked:admin-session>"
