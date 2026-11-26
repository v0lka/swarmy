"""AGENT.md module manifests: Pydantic model + frontmatter parser (arch §8.2, T1.5.2).

Every subagent module folder carries a required ``AGENT.md`` (arch §8.1): a
``---``-fenced YAML frontmatter block followed by the module system prompt.
``AgentModuleManifest`` validates the frontmatter strictly - unknown fields
are rejected (fail-fast, arch §8.3) and every type mismatch produces an
error naming the offending field.

The optional ``result`` field (AD-3) declares the module response-format
class as ``"<module>/tools/result.py:ClassName"``. Only the *shape* of the
reference is validated here; the loader (roadmap T1.5.3) performs the
actual class import and passes it to L0 as ``response_format``.

``tools/`` and ``skills/`` are deliberately NOT frontmatter fields: the
loader attaches those folders automatically (arch §8.2, spec §4.2).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
)

from swarmy.tools.projector import UNTRUSTED_BEGIN, UNTRUSTED_END

# ``"<module>/tools/result.py:ClassName"`` (AD-3): exactly one module-folder
# segment, the fixed ``tools/result.py`` suffix, then the exported class name.
_RESULT_SPEC_PATTERN = re.compile(
    r"^(?P<module_name>[A-Za-z0-9][A-Za-z0-9_-]*)/tools/result\.py:"
    r"(?P<class_name>[A-Za-z_][A-Za-z0-9_]*)$"
)

_FRONTMATTER_FENCE = "---"


class ManifestError(ValueError):
    """Raised when an ``AGENT.md`` file is missing or cannot be parsed (arch §8.2).

    Messages always name the offending ``AGENT.md`` path (or field), so the
    loader (T1.5.3) can aggregate problems across all modules fail-fast.
    """


class Utf8Error(ValueError):
    """A file that must be UTF-8 is not decodable as UTF-8 (#57, #62).

    The message always names the offending path, so every typed fail-fast
    contract (``ManifestError``, ``SecretsConfigError``, ``ConfigError``,
    loader ``LoadProblem``) can surface the decode failure without a raw
    ``UnicodeDecodeError`` traceback escaping the boundary.
    """

    def __init__(self, path: Path, exc: UnicodeDecodeError) -> None:
        """Name the file, the byte offset and the codec reason of the failure."""
        super().__init__(
            f"{path}: not valid UTF-8 at byte {exc.start}: {exc.reason}"
        )
        self.path = path


def read_utf8(path: Path) -> str:
    """Read *path* as UTF-8 with a typed decode failure (shared #57/#62 helper).

    The strict-UTF-8 read of every fail-fast config/manifest surface: bytes
    are read first, then decoded explicitly, so a non-UTF-8 file raises the
    typed :class:`Utf8Error` (naming the file) instead of a raw
    ``UnicodeDecodeError`` — which is a ``ValueError`` and escapes every
    ``except OSError`` guard. ``OSError`` propagates unchanged (unreadable
    files keep each caller's existing handling).
    """
    data = path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Utf8Error(path, exc) from exc


class ResultSpec(BaseModel):
    """Parsed ``result`` reference: module folder and response-format class (AD-3)."""

    model_config = ConfigDict(frozen=True)

    module_name: str
    class_name: str


#: Maximum length of a manifest ``description`` after normalization (F-9).
#: The description is model-facing text (the orchestrator picks ``task()``
#: targets by it); the cap bounds a module author's reach into the
#: orchestrator's trusted instruction block while leaving ample room for
#: honest routing text.
MAX_DESCRIPTION_CHARS: Final[int] = 400

#: In-content occurrences of the verbatim §6.8 markers are defused with the
#: projector's ``[defused:...]`` form so a description cannot open or close
#: an untrusted block inside the roster (F-9; same mechanism as D24).
_DEFUSED_BEGIN: Final[str] = f"[defused:{UNTRUSTED_BEGIN[1:-1]}]"
_DEFUSED_END: Final[str] = f"[defused:{UNTRUSTED_END[1:-1]}]"


def normalize_description(text: str) -> str:
    """Normalize a manifest description for every model-facing surface (F-9).

    One shared treatment for the roster of the orchestrator prompt and the
    ``SubAgent`` dict: control characters (including newlines) become plain
    spaces, whitespace runs collapse, in-content occurrences of the verbatim
    §6.8 untrusted markers are defused (D24 mechanism), and the result is
    stripped. Length is *not* capped here — :class:`AgentModuleManifest`
    validates the cap as a load problem so an over-long description fails
    fast instead of being silently truncated.
    """
    replaced = text.translate(dict.fromkeys([*range(32), 127, *range(0x80, 0xA0)], " "))
    replaced = replaced.replace(UNTRUSTED_BEGIN, _DEFUSED_BEGIN)
    replaced = replaced.replace(UNTRUSTED_END, _DEFUSED_END)
    return " ".join(replaced.split())


def parse_result_spec(value: str) -> ResultSpec:
    """Validate the ``result`` shape ``"<module>/tools/result.py:ClassName"`` (AD-3).

    Only the reference shape is checked - no class is imported here; the
    loader resolves the Pydantic class when building the ``SubAgent`` dict
    (arch §8.3).
    """
    match = _RESULT_SPEC_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(
            "'result' must have the form '<module>/tools/result.py:ClassName' "
            f"(AD-3), got {value!r}"
        )
    return ResultSpec(
        module_name=match.group("module_name"),
        class_name=match.group("class_name"),
    )


class AgentModuleManifest(BaseModel):
    """Strict model of the ``AGENT.md`` YAML frontmatter (arch §8.2).

    Unknown fields are validation errors (``extra="forbid"``); ``tools`` and
    ``skills`` are intentionally absent - the loader wires those folders
    automatically (spec §4.2).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str  # ← arch §8.2 (required)
    description: str  # ← arch §8.2 (required)
    model: str | None = None  # "provider:model" override, else orchestrator model
    mode: Literal["isolated", "fork"] = "isolated"  # ← arch §8.2 (default isolated)
    interrupt_on: dict[str, bool] = Field(default_factory=dict)  # ← arch §8.2 (per-tool gates)
    events: list[str] = Field(default_factory=list)  # checked vs EventRegistry (arch §8.4)
    guardrails: str = "./guardrails.yaml"  # ← arch §8.2 (default per §8.2)
    result: str | None = None  # AD-3: "<module>/tools/result.py:Class" → response_format

    @field_validator("name", "description")
    @classmethod
    def _non_empty_text(cls, value: str, info: ValidationInfo) -> str:
        """Reject empty or whitespace-only required text fields with a precise message."""
        if not value.strip():
            field = info.field_name or "<unknown>"
            raise ValueError(f"field '{field}' must be a non-empty string")
        return value

    @field_validator("description")
    @classmethod
    def _normalize_model_facing_description(
        cls, value: str, info: ValidationInfo
    ) -> str:
        """Normalize and length-cap the description (F-9, review).

        The description reaches the orchestrator system prompt (instruction
        position) and the ``SubAgent`` dict; it is stored normalized (control
        characters flattened, whitespace collapsed, embedded §6.8 markers
        defused) and over-length descriptions are a validation error — the
        loader aggregates them as a load problem instead of truncating
        silently.
        """
        normalized = normalize_description(value)
        if len(normalized) > MAX_DESCRIPTION_CHARS:
            field = info.field_name or "description"
            raise ValueError(
                f"field '{field}' must be at most {MAX_DESCRIPTION_CHARS} "
                f"characters after normalization (got {len(normalized)})"
            )
        return normalized

    @field_validator("result")
    @classmethod
    def _valid_result_shape(cls, value: str | None) -> str | None:
        """Check the AD-3 path shape without importing the referenced class."""
        if value is not None:
            parse_result_spec(value)
        return value


class ParsedAgentModule(BaseModel):
    """Outcome of parsing one ``AGENT.md``: manifest, system prompt, source path."""

    model_config = ConfigDict(frozen=True)

    manifest: AgentModuleManifest
    system_prompt: str
    source: Path


def split_frontmatter(text: str) -> tuple[str, str]:
    """Split ``AGENT.md`` text into ``(frontmatter_yaml, system_prompt)`` (arch §8.1).

    The frontmatter must be a ``---``-fenced block starting on the first
    line; everything after the closing fence becomes the system prompt,
    stripped of surrounding whitespace. A ``---`` line inside the body is
    body text - only the first closing fence terminates the frontmatter.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != _FRONTMATTER_FENCE:
        raise ManifestError("AGENT.md must start with a '---' frontmatter fence")
    closing: int | None = None
    for index in range(1, len(lines)):
        if lines[index].strip() == _FRONTMATTER_FENCE:
            closing = index
            break
    if closing is None:
        raise ManifestError("unterminated YAML frontmatter: missing closing '---'")
    frontmatter = "\n".join(lines[1:closing])
    system_prompt = "\n".join(lines[closing + 1 :]).strip()
    return frontmatter, system_prompt


def parse_agent_module(agent_md_path: Path) -> ParsedAgentModule:
    """Read one ``AGENT.md``: frontmatter → manifest, body → system prompt (§8.2).

    Raises ``ManifestError`` naming the file for: missing file, missing or
    unterminated frontmatter fence, malformed YAML, non-mapping frontmatter,
    and any manifest validation failure (unknown field, wrong type, missing
    ``name``/``description``, malformed ``result`` reference).
    """
    if not agent_md_path.is_file():
        raise ManifestError(f"AGENT.md not found: {agent_md_path}")
    try:
        text = read_utf8(agent_md_path)
    except Utf8Error as exc:
        # Non-UTF-8 module files are a ManifestError, not a raw
        # UnicodeDecodeError: the loader's aggregate fail-fast collection
        # keeps collecting the problems of the other modules (#57, option b).
        raise ManifestError(str(exc)) from exc
    try:
        frontmatter, system_prompt = split_frontmatter(text)
    except ManifestError as exc:
        raise ManifestError(f"{agent_md_path}: {exc}") from exc
    try:
        data: object = yaml.safe_load(frontmatter)
    except yaml.YAMLError as exc:
        raise ManifestError(f"{agent_md_path}: invalid YAML frontmatter: {exc}") from exc
    if data is None:
        data = {}  # empty block: validation reports the missing required fields
    if not isinstance(data, dict):
        raise ManifestError(
            f"{agent_md_path}: frontmatter must be a YAML mapping, "
            f"got {type(data).__name__}"
        )
    try:
        manifest = AgentModuleManifest.model_validate(data)
    except ValidationError as exc:
        raise ManifestError(f"{agent_md_path}: invalid AGENT.md frontmatter:\n{exc}") from exc
    return ParsedAgentModule(
        manifest=manifest,
        system_prompt=system_prompt,
        source=agent_md_path,
    )
