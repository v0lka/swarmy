"""T3.1.1 acceptance criteria: SessionConfig resolution, fail-fast list, snapshot.

Roadmap T3.1.1:
* the arch §12.1 example config parses in full;
* resolution priority CLI > file > code defaults is enforced;
* three config problems produce a three-entry fail-fast report;
* the ``session.yaml`` snapshot mirrors the applied config and contains no
  secret values (only the ``<masked:name>`` references, AD-5).
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml

from swarmy.core.config import (
    ConfigError,
    SecretsConfig,
    SessionConfig,
    load_secrets,
    snapshot_yaml,
    write_secrets,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

# The arch §12.1 reference example, verbatim section structure.
ARCH_EXAMPLE = """
target:
  base_url: "https://target.example.com"
  notes: "authorized engagement, contract #42"
scope:
  domains: ["target.example.com", "api.target.example.com"]
  ip_subnets: ["203.0.113.0/24"]
  ports: [80, 443]
  schemes: ["https"]
profile: normal
mode: interactive
model: "anthropic:claude-3-5-sonnet"
limits:
  rate_limit: 5
  max_concurrent_requests: 8
  max_body_bytes: 5242880
  max_redirect_depth: 5
  total_request_budget: 5000
  connect_timeout_s: 10
  read_timeout_s: 30
memory:
  search_backend: fts5
context:
  budgets: {http_preview_bytes: 20000, memory_result_bytes: 8000}
guardrails:
  engine_rules: true
judge:
  tools: []
  model: null
  confidence_threshold: 0.7
  timeout_s: 15
policies:
  - {on: FindingCandidate, action: notify_orchestrator, template: verify_finding}
mcp_servers: []
agents_dirs: ["./agents"]
"""


def _write(tmp_path: Path, text: str) -> Path:
    """Write one YAML document into the tmp dir."""
    path = tmp_path / "cfg.yaml"
    path.write_text(text, encoding="utf-8")
    return path


@contextlib.contextmanager
def _problem(tmp_path: Path, text: str) -> Iterator[ConfigError]:
    """Load a broken config and hand the raised ``ConfigError`` to the test."""
    try:
        SessionConfig.load(config_path=_write(tmp_path, text))
    except ConfigError as error:
        yield error
    else:  # pragma: no cover - the input is constructed invalid
        raise AssertionError("broken config unexpectedly loaded")


class TestFullExampleParses:
    """AC: the arch §12.1 example config parses in full (test)."""

    def test_example_parses_whole(self, tmp_path: Path) -> None:
        config = SessionConfig.load(config_path=_write(tmp_path, ARCH_EXAMPLE))
        assert str(config.target.base_url) == "https://target.example.com/"
        assert config.profile == "normal"
        assert config.mode == "interactive"
        assert config.model == "anthropic:claude-3-5-sonnet"
        assert config.limits.rate_limit == 5
        assert config.limits.max_concurrent_requests == 8
        assert config.memory.search_backend == "fts5"
        assert config.context.budgets["http_preview_bytes"] == 20000
        assert config.guardrails.engine_rules is True
        assert config.judge.model is None
        assert config.judge.confidence_threshold == 0.7
        assert [policy.template for policy in config.policies] == ["verify_finding"]
        assert config.agents_dirs == [Path('./agents')]


class TestResolutionPriority:
    """AC: priority resolution is covered by tests (CLI beats file, file beats defaults)."""

    def test_cli_overrides_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path, ARCH_EXAMPLE)
        config = SessionConfig.load(
            cli_overrides={"profile": "paranoid", "mode": "mission"}, config_path=path
        )
        assert config.profile == "paranoid"
        assert config.mode == "mission"

    def test_file_overrides_defaults(self, tmp_path: Path) -> None:
        path = _write(tmp_path, ARCH_EXAMPLE)
        config = SessionConfig.load(config_path=path)
        assert config.profile == "normal"  # from the file
        assert config.limits.rate_limit == 5  # from the file

    def test_defaults_when_no_file_and_no_cli(self) -> None:
        config = SessionConfig.load(
            cli_overrides={
                "target": {"base_url": "https://t.example.com"},
                "scope": {"domains": ["t.example.com"]},
            }
        )
        # conservative code defaults (arch §12.2 last resolution layer)
        assert config.profile == "normal"
        assert config.limits.rate_limit == 5
        assert config.limits.total_request_budget == 5000
        assert config.guardrails.engine_rules is True
        assert config.policies == []

    def test_absent_cli_flag_does_not_shadow_the_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path, ARCH_EXAMPLE)
        config = SessionConfig.load(
            cli_overrides={"profile": None}, config_path=path  # flag not passed
        )
        assert config.profile == "normal"


class TestFailFastList:
    """AC: three config errors give three report entries (fail-fast list)."""

    def test_three_problems_three_report_entries(self, tmp_path: Path) -> None:
        broken = """
target:
  base_url: "https://target.example.com"
profile: ultra-paranoid
mode: hyperdrive
mystery_section: {}
"""
        with _problem(tmp_path, broken) as error:
            assert len(error.problems) == 3
            joined = "\n".join(error.problems)
            assert "profile" in joined
            assert "mode" in joined
            assert "mystery_section" in joined
            assert str(len(error.problems)) in str(error)

    def test_missing_file_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            SessionConfig.load(config_path=tmp_path / "nope.yaml")


class TestSnapshot:
    """AC: the snapshot matches the applied config and contains no secrets (test)."""

    def test_snapshot_mirrors_applied_config(self, tmp_path: Path) -> None:
        path = _write(tmp_path, ARCH_EXAMPLE)
        config = SessionConfig.load(config_path=path)
        document: dict[str, object] = yaml.safe_load(snapshot_yaml(config))
        assert document["profile"] == config.profile
        assert document["mode"] == config.mode
        limits = document["limits"]
        assert isinstance(limits, dict)
        assert limits["rate_limit"] == config.limits.rate_limit
        assert document["secrets"] == {}

    def test_snapshot_carries_no_secret_values(self, tmp_path: Path) -> None:
        config = SessionConfig.load(
            cli_overrides={
                "target": {"base_url": "https://t.example.com"},
                "scope": {"domains": ["t.example.com"]},
            }
        )
        secrets = SecretsConfig(tokens={"api_key": "sk-super-secret-value-123"})
        secrets_path = tmp_path / "secrets.yaml"
        write_secrets(secrets_path, secrets)
        assert (secrets_path.stat().st_mode & 0o777) == 0o600  # POSIX mode kept
        text = snapshot_yaml(config, load_secrets(secrets_path))
        assert "sk-super-secret-value-123" not in text
        assert "<masked:api_key>" in text
