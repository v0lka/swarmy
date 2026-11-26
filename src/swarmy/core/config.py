"""Session configuration (arch §12) — T3.1.1 + operator-secrets scaffold (T2.3.3).

This module carries the full ``SessionConfig`` composition (arch §12.1/§12.2)
plus the operator-secrets half of arch §12.3 / AD-5 (T2.3.3):

* ``secrets.yaml`` lives in the session folder next to ``session.yaml`` and
  must be mode ``0600`` (arch §3.3). The mode is enforced on load and on
  write. **Windows limitation** (documented per roadmap T2.3.3): ``os.chmod``
  on Windows cannot express POSIX modes (it only toggles the read-only
  attribute), and ACL hardening is out of scope for v0.1 — on Windows the
  loader skips the mode step and the operator must protect the session
  folder by other means.
* categories ``auth_headers`` / ``cookies`` / ``tokens`` hold named values;
  names are unique across categories so ``<masked:secret-name>`` references
  stay unambiguous.
* secrets are addressed **by name** in config and tools; raw values never
  enter ``session.yaml``, the journal, chat or LLM context — only the
  ``<masked:secret-name>`` reference of arch §6.8 (format canonical in
  :mod:`swarmy.tools.projector`). Raw values go to evidence files as-is
  (spec §8.7).

Until T3.1.2 wires session start, callers pass the loaded values
to :class:`~swarmy.tools.projector.ContextProjector` explicitly via
its constructor (``secrets=``/``secret_patterns=``).
"""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationError,
    field_validator,
    model_validator,
)

from swarmy.modules.manifest import Utf8Error, read_utf8
from swarmy.tools.limits import ResourceLimits
from swarmy.tools.projector import DEFAULT_BUDGETS, mask_reference
from swarmy.tools.scope import ScopeEntries

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

#: Canonical file name inside the session folder (arch §3.3, §12.3).
SECRETS_FILENAME: Final[str] = "secrets.yaml"

#: Owner-only permission mode required for the secrets file (arch §3.3).
SECRETS_FILE_MODE: Final[int] = 0o600


class SecretCategory(StrEnum):
    """The three secret categories of arch §12.3."""

    AUTH_HEADERS = "auth_headers"
    COOKIES = "cookies"
    TOKENS = "tokens"


class SecretsConfigError(Exception):
    """Raised when a secrets file cannot be loaded (fail-fast, arch §4.5 style).

    Carries *all* problems of the load — unreadable file, invalid structure,
    validation errors and permission problems are reported together.
    """

    def __init__(self, problems: list[str]) -> None:
        """Build the error from the collected problems (never empty)."""
        lines = "\n".join(f"  - {problem}" for problem in problems)
        super().__init__(f"secrets.yaml rejected, {len(problems)} problem(s):\n{lines}")
        self.problems: tuple[str, ...] = tuple(problems)


class SecretsConfig(BaseModel):
    """Named operator secrets by category (arch §12.3, AD-5).

    A ``SecretsConfig`` instance holds **raw values** in memory only; every
    model-bound surface receives :meth:`masked_snapshot` references instead,
    and the projector (§6.8) receives the values via :meth:`secret_values`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    auth_headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    tokens: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_names(self) -> SecretsConfig:
        """Aggregate name problems: empty names/values, duplicates across categories."""
        problems: list[str] = []
        seen: dict[str, SecretCategory] = {}
        for category in SecretCategory:
            values: Mapping[str, str] = getattr(self, category.value)
            for name, value in values.items():
                if not name:
                    problems.append(f"{category.value}: secret names must be non-empty")
                if not value:
                    problems.append(f"{category.value}.{name}: secret values must be non-empty")
                if name in seen and name:
                    problems.append(
                        f"duplicate secret name {name!r} in {category.value} "
                        f"and {seen[name].value} (names must be unique across categories)"
                    )
                elif name:
                    seen[name] = category
        if problems:
            raise ValueError("; ".join(problems))
        return self

    def iter_secrets(self) -> Iterator[tuple[SecretCategory, str, str]]:
        """Yield ``(category, name, raw_value)`` for every stored secret."""
        for category in SecretCategory:
            for name, value in getattr(self, category.value).items():
                yield category, name, value

    def secret_values(self) -> dict[str, str]:
        """``name → raw value`` map for projector wiring (§6.8 step 2).

        The result feeds ``ContextProjector(secrets=...)``; it must never be
        logged, journaled or placed into a session snapshot.
        """
        return {name: value for _category, name, value in self.iter_secrets()}

    def masked_snapshot(self) -> dict[str, str]:
        """Snapshot-safe ``"<category>.<name>" → "<masked:name>"`` references.

        This is the *only* shape of secret data allowed in a ``session.yaml``
        snapshot: names are addressable, values are the §6.8 masked
        references — raw values are structurally absent.
        """
        return {
            f"{category.value}.{name}": mask_reference(name)
            for category, name, _value in self.iter_secrets()
        }

    def secret_value(self, category: SecretCategory | str, name: str) -> str:
        """Resolve one secret by category and name (arch §12.3: addressing by name).

        Raises:
            ValueError: when ``category`` is not a valid category value.
            KeyError: when ``name`` is unknown in that category (the message
                lists the names that exist there).
        """
        try:
            resolved = SecretCategory(category)
        except ValueError as exc:
            allowed = [item.value for item in SecretCategory]
            msg = f"unknown secret category {category!r}; allowed: {allowed}"
            raise ValueError(msg) from exc
        values: Mapping[str, str] = getattr(self, resolved.value)
        if name not in values:
            known = ", ".join(sorted(values))
            msg = f"unknown secret {resolved.value}.{name!r}; known names: {known or 'none'}"
            raise KeyError(msg) from None
        return values[name]


def _enforce_private_mode(path: Path) -> None:
    """Tighten the file to owner-only ``0600`` (POSIX only; no-op elsewhere).

    Windows limitation (documented per roadmap T2.3.3): ``os.chmod`` on
    Windows cannot express the POSIX ``0600`` mode — it only toggles the
    read-only attribute — and ACL hardening is out of scope for v0.1, so on
    Windows this function degrades to a no-op.
    """
    if os.name != "posix":
        return
    path.chmod(SECRETS_FILE_MODE)


def load_secrets(path: Path) -> SecretsConfig:
    """Load and validate ``secrets.yaml``, enforcing mode ``0600`` (arch §12.3).

    The file must exist (session start is fail-fast, arch §4.5); YAML and
    validation problems are aggregated into one :class:`SecretsConfigError`.
    On POSIX the file is tightened to ``0600`` on every load (the mode is a
    property of the session folder, not of the call site); see
    :func:`_enforce_private_mode` for the documented Windows limitation.

    Raises:
        SecretsConfigError: with every problem of the load (never empty).
    """
    problems: list[str] = []
    if not path.is_file():
        raise SecretsConfigError([f"secrets file not found: {path}"])
    try:
        text = read_utf8(path)
    except OSError as exc:
        raise SecretsConfigError([f"secrets file {path} is unreadable: {exc}"]) from exc
    except Utf8Error as exc:
        # Non-UTF-8 secrets files get the documented aggregated typed error,
        # never a raw UnicodeDecodeError traceback (#62, shared read_utf8).
        raise SecretsConfigError([str(exc)]) from exc
    try:
        raw: object = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SecretsConfigError([f"secrets file {path} is not valid YAML: {exc}"]) from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SecretsConfigError(
            [
                f"secrets file {path}: top level must be a mapping of "
                f"{[category.value for category in SecretCategory]}"
            ]
        )
    try:
        config = SecretsConfig.model_validate(raw)
    except ValidationError as exc:
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"]) or "<top>"
            problems.append(f"{location}: {error['msg']}")
        raise SecretsConfigError(problems) from exc
    try:
        _enforce_private_mode(path)
    except OSError as exc:
        problems.append(f"could not enforce mode 600 on {path}: {exc}")
        raise SecretsConfigError(problems) from exc
    return config


def write_secrets(path: Path, config: SecretsConfig) -> None:
    """Serialize ``config`` to ``secrets.yaml``, creating/keeping mode ``0600``.

    On POSIX the file is created with owner-only mode and re-chmodded after
    writing (``O_TRUNC`` on an existing file would keep its old, possibly
    looser, mode). On Windows the mode step is a documented no-op (see
    :func:`_enforce_private_mode`).

    This is the only sanctioned path for raw secret values leaving the
    process — into the ``0600`` session file itself.
    """
    text = yaml.safe_dump(config.model_dump(), sort_keys=False, allow_unicode=True)
    if os.name == "posix":
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECRETS_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
    else:  # Windows: os.open mode is not POSIX-expressible — documented limitation
        path.write_text(text, encoding="utf-8")
    _enforce_private_mode(path)


# ---------------------------------------------------------------------------
# SessionConfig (arch §12.1/§12.2, T3.1.1).
# ---------------------------------------------------------------------------

#: File name of the session-config document inside the session folder (arch §3.3).
SESSION_CONFIG_FILENAME: Final[str] = "session.yaml"

#: HITL strictness profiles (arch §7.2, §12.1 ``profile``).
PROFILE_VALUES: Final[tuple[str, ...]] = ("paranoid", "normal", "yolo")

#: Orchestrator autonomy modes (arch §9.5, §12.1 ``mode``).
MODE_VALUES: Final[tuple[str, ...]] = ("interactive", "mission")

#: Conservative code defaults for the ``limits`` section (arch §12.2: the last
#: resolution layer). The values are the arch §12.1 reference example — the
#: invariant-protecting shape every session falls back to.
_DEFAULT_LIMITS = ResourceLimits(
    rate_limit=5,
    max_concurrent_requests=8,
    max_body_bytes=5_242_880,
    max_redirect_depth=5,
    total_request_budget=5000,
    connect_timeout_s=10,
    read_timeout_s=30,
)


class ConfigError(Exception):
    """Raised when a session config cannot be resolved (fail-fast, arch §4.5).

    Carries *all* problems of the resolution — unreadable/missing file, bad
    YAML, non-mapping document and every Pydantic validation error are
    reported together as one list (arch §12.1: "ошибки — fail-fast списком").
    ``str(exception)`` renders the full report; ``problems`` holds the lines.
    """

    def __init__(self, problems: list[str]) -> None:
        """Build the error from the collected problems (never empty)."""
        lines = "\n".join(f"  - {problem}" for problem in problems)
        super().__init__(f"session config rejected, {len(problems)} problem(s):\n{lines}")
        self.problems: tuple[str, ...] = tuple(problems)


class TargetConfig(BaseModel):
    """The ``target`` section: base URL of the authorized target (arch §12.1)."""

    model_config = ConfigDict(extra="forbid")

    base_url: HttpUrl
    notes: str = ""  # e.g. "authorized engagement, contract #42"


class MemoryConfig(BaseModel):
    """The ``memory`` section (arch §12.1): FTS5 in v0.1, ``vec`` is phase 2."""

    model_config = ConfigDict(extra="forbid")

    search_backend: Literal["fts5", "vec"] = "fts5"


class ContextConfig(BaseModel):
    """The ``context`` section (arch §12.1): projector byte budgets (§6.8).

    Keys are the ``<tool_class>_bytes`` budget names of
    :class:`~swarmy.tools.projector.ProjectorConfig`; the defaults are the
    conservative projector defaults (``http_preview_bytes``/``memory_result_bytes``).
    """

    model_config = ConfigDict(extra="forbid")

    budgets: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_BUDGETS))

    @field_validator("budgets")
    @classmethod
    def _budgets_positive(cls, value: dict[str, int]) -> dict[str, int]:
        """Reject non-positive budgets (a zero budget would truncate everything)."""
        non_positive = sorted(name for name, budget in value.items() if budget < 1)
        if non_positive:
            raise ValueError(f"budgets must be >= 1 byte, offending keys: {non_positive}")
        return value


class GuardrailsConfig(BaseModel):
    """The ``guardrails`` section (arch §12.1): layer-2 engine rules toggle.

    Only the engine-rules layer is switchable — layer 1 (invariants) is never
    configurable (T1.4.3) and layer 3 (module rules) ships with modules.
    """

    model_config = ConfigDict(extra="forbid")

    engine_rules: bool = True


class JudgeConfig(BaseModel):
    """The ``judge`` section (arch §12.1, §6.7): the LLM judge band.

    ``model=None`` keeps the judge switched off; ``tools`` lists the risk
    classes served by the pre-call band (empty list = post-call only).
    """

    model_config = ConfigDict(extra="forbid")

    tools: list[str] = Field(default_factory=list)
    model: str | None = None
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    timeout_s: float = Field(default=15.0, gt=0.0)


class PolicySpec(BaseModel):
    """One declarative event policy (arch §9.3, §12.1 ``policies``).

    ``on`` names one event type or a list of them; ``action`` is the reaction
    class; ``template`` optionally keys into the policy notification templates
    of :mod:`swarmy.core.prompts` (built-in defaults land with T3.2.2).
    """

    model_config = ConfigDict(extra="forbid")

    on: str | list[str]
    action: Literal["notify_orchestrator", "notify_tui", "ignore"]
    template: str | None = None


class SessionConfig(BaseModel):
    """Immutable, fully resolved configuration of one session (arch §12.1-§12.2).

    Build it only through :meth:`load` (resolution chain CLI → file → code
    defaults) or by direct construction in tests. The model is ``frozen`` —
    runtime changes to scope/profile/mode go through ``OperatorDecision``
    and are journaled, never assigned here (arch §12.2).

    Sections mirror the arch §12.1 YAML example exactly; unknown keys are
    rejected (``extra="forbid"``), which is also the config-slot proof that
    layer-1 invariants are not configurable (T1.4.3). Secrets are addressed
    by name only — this model structurally cannot hold a secret value (AD-5).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: TargetConfig
    scope: ScopeEntries = Field(default_factory=ScopeEntries)
    profile: Literal["paranoid", "normal", "yolo"] = "normal"  # ← arch §7.2
    mode: Literal["interactive", "mission"] = "interactive"  # ← arch §9.5
    model: str | None = None  # "provider:model" (D1); None = engine default selection
    limits: ResourceLimits = Field(default_factory=lambda: _DEFAULT_LIMITS.model_copy())
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    guardrails: GuardrailsConfig = Field(default_factory=GuardrailsConfig)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    policies: list[PolicySpec] = Field(default_factory=list)  # defaults live in §9.3 wiring
    mcp_servers: list[str] = Field(default_factory=list)
    agents_dirs: list[Path] = Field(default_factory=list)  # user module roots (spec §4.5)

    @field_validator("policies", mode="before")
    @classmethod
    def _rename_yaml_boolean_on_key(cls, value: object) -> object:
        """Normalize YAML 1.1's boolean ``on`` key back to ``"on"``.

        PyYAML implements YAML 1.1, where the plain scalar ``on`` resolves to
        the boolean ``True`` — the arch §12.1 example (``{on: FindingCandidate,
        ...}``) therefore arrives with a ``True`` key. This schema has no
        boolean keys, so such keys are renamed to the ``on`` field name before
        the ``PolicySpec`` models are built.
        """
        if not isinstance(value, list):
            return value
        fixed: list[object] = []
        for item in value:
            if isinstance(item, dict) and "on" not in item and True in item:
                renamed = {"on": item[True]}
                for key, entry in item.items():
                    if key is not True:
                        renamed[str(key)] = entry
                item = renamed
            fixed.append(item)
        return fixed

    @classmethod
    def load(
        cls,
        cli_overrides: Mapping[str, object] | None = None,
        config_path: Path | None = None,
    ) -> SessionConfig:
        """Resolve the session config (arch §12.2) and validate it fail-fast.

        Resolution order (highest priority first): CLI flags → session file →
        conservative code defaults (the field defaults of this model; the
        strictness profile layer of arch §12.2 is the profile field itself).
        ``cli_overrides`` maps top-level section names to values; entries with
        a ``None`` value are treated as absent CLI flags and skipped, so an
        unpassed flag can never shadow the file.

        All problems — missing/unreadable file, invalid YAML, non-mapping
        document, every field validation error — are collected into one
        :class:`ConfigError` report (arch §4.5/§12.1: fail-fast list).

        Raises:
            ConfigError: with every problem of the resolution (never empty).
        """
        problems: list[str] = []
        merged: dict[str, object] = {}
        if config_path is not None:
            if not config_path.is_file():
                problems.append(f"session config file not found: {config_path}")
            else:
                merged, problems = cls._read_file(config_path)
        for key, value in (cli_overrides or {}).items():
            if value is not None:  # None = CLI flag absent (must not shadow the file)
                merged[key] = value
        if not problems:
            try:
                return cls.model_validate(merged)
            except ValidationError as exc:
                problems.extend(_validation_report(exc))
        raise ConfigError(problems)

    @classmethod
    def _read_file(cls, path: Path) -> tuple[dict[str, object], list[str]]:
        """Read and parse one YAML config document (arch §12.1, AD-1).

        Returns ``(data, problems)``: the (possibly empty) mapping and any
        file-level problems. A non-mapping document is reported instead of
        being passed to validation.
        """
        try:
            text = read_utf8(path)
        except OSError as exc:
            return {}, [f"session config file {path} is unreadable: {exc}"]
        except Utf8Error as exc:
            # A non-UTF-8 session.yaml is a ConfigError problem line naming
            # the file, not a raw ValueError escaping the merge loop (#62).
            return {}, [str(exc)]
        try:
            raw: object = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            return {}, [f"session config file {path} is not valid YAML: {exc}"]
        if raw is None:
            return {}, []
        if not isinstance(raw, dict):
            return {}, [
                f"session config file {path}: top level must be a mapping of section names"
            ]
        return {str(key): value for key, value in raw.items()}, []


def _validation_report(exc: ValidationError) -> list[str]:
    """Render every Pydantic error as one ``"location: message"`` report line."""
    lines: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<top>"
        lines.append(f"{location}: {error['msg']}")
    return lines


def snapshot_yaml(config: SessionConfig, secrets: SecretsConfig | None = None) -> str:
    """Render the ``session.yaml`` audit snapshot (arch §3.3, §12.2, AD-5).

    The snapshot mirrors the *applied* configuration (post-resolution) and is
    written at session start (and after operator scope changes) into the
    session folder. Secret values are structurally absent: ``secrets`` is
    rendered only as the ``<category>.<name> → <masked:name>`` reference map
    of :meth:`SecretsConfig.masked_snapshot` (arch §6.8), so the snapshot is
    safe to share for audit.
    """
    data: dict[str, object] = config.model_dump(mode="json")
    data["secrets"] = secrets.masked_snapshot() if secrets is not None else {}
    header = (
        "# session.yaml — audit snapshot of the resolved session configuration\n"
        "# (arch §3.3, §12.2). Written at session start and on operator scope\n"
        "# changes; source of truth for 'what this session actually ran with'.\n"
        "# Operator secrets live in secrets.yaml (mode 0600) and appear here\n"
        "# only as <masked:name> references (AD-5, arch §12.3).\n"
    )
    return header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


__all__ = [
    "MODE_VALUES",
    "PROFILE_VALUES",
    "SECRETS_FILENAME",
    "SECRETS_FILE_MODE",
    "SESSION_CONFIG_FILENAME",
    "ConfigError",
    "ContextConfig",
    "GuardrailsConfig",
    "JudgeConfig",
    "MemoryConfig",
    "PolicySpec",
    "SecretCategory",
    "SecretsConfig",
    "SecretsConfigError",
    "SessionConfig",
    "TargetConfig",
    "load_secrets",
    "snapshot_yaml",
    "write_secrets",
]
